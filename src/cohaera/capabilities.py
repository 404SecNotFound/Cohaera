"""Exact tool capability manifests.

``_classify`` guesses what a tool does from its name. The guess has been wrong
in both directions and each round of review has found new cases:

    budget_report      -> read_only    because "get" is inside "budget"
    forget_password    -> read_only    because "get" is inside "forget"
    postmortem_read    -> egress       because "post" is inside "postmortem"

Whole-token matching fixed those three. It cannot fix the general case, because
the general case is not a lexical problem. ``sync_to_partner`` is egress and
``sync_local_cache`` is not, and no amount of tokenising tells them apart. A
tool called ``run_playbook`` could be anything.

A manifest is the answer the heuristic is standing in for: the producer states,
per exact tool ID, what the tool actually does. Cohaera then uses the declared
capability and falls back to the guess only when there is no declaration.

Note the precedence. A manifest outranks the producer's per-call ``reversible``
flag, and that ordering is deliberate. ``reversible`` arrives on the event, in
band, from the same path an attacker would control to hide an action (SEC-03).
The manifest is loaded out of band from a file the operator chose, so it is the
stronger of the two claims about the same tool.

The manifest is not signed here. Signing needs a key distribution story that
does not exist yet, and shipping a signature field that nothing verifies would
be worse than shipping none. What is here is the digest, recorded in every
verdict, so that two runs disagreeing about what a tool does are distinguishable
after the fact.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Effects, in the vocabulary the review's F2 asks for.
EFFECT_READ = "read"
EFFECT_WRITE = "write"
EFFECT_DELETE = "delete"
EFFECT_EXECUTE = "execute"
EFFECT_EGRESS = "egress"
VALID_EFFECTS = frozenset({EFFECT_READ, EFFECT_WRITE, EFFECT_DELETE,
                           EFFECT_EXECUTE, EFFECT_EGRESS})

# Effects that make a call consequential, mapped onto the class vocabulary the
# checks already speak. Egress wins because data leaving the trust boundary is
# the property a concealment or taint check cares about most, and reversibility
# says nothing about it.
_EGRESS = {EFFECT_EGRESS}
_STATE_CHANGE = {EFFECT_WRITE, EFFECT_DELETE, EFFECT_EXECUTE}


class ManifestError(ValueError):
    """The manifest file is not a manifest. Refuse it; do not half-load it."""


@dataclass(frozen=True)
class Capability:
    """What one exact tool ID is declared to do."""

    tool_id: str
    effects: frozenset[str]
    reversible: bool | None = None
    destination: str | None = None
    requires_approval: bool = False
    sensitive_args: tuple[str, ...] = ()

    @property
    def klass(self) -> str:
        if self.effects & _EGRESS:
            return "egress"
        if self.effects & _STATE_CHANGE:
            return "state_change"
        if self.effects & {EFFECT_READ}:
            return "read_only"
        return "unknown"

    @property
    def consequential(self) -> bool:
        return self.klass in {"state_change", "egress"}


@dataclass(frozen=True)
class CapabilityManifest:
    """A producer's declaration of its tool surface."""

    producer: str = ""
    manifest_version: str = ""
    producer_schema_version: str = ""
    tools: dict[str, Capability] = field(default_factory=dict)
    digest: str = ""

    @property
    def loaded(self) -> bool:
        return bool(self.tools)

    def get(self, tool_id: Any) -> Capability | None:
        if not isinstance(tool_id, str) or not tool_id:
            return None
        return self.tools.get(tool_id)

    def klass_for(self, tool_id: Any) -> str | None:
        cap = self.get(tool_id)
        return cap.klass if cap is not None else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "producer": self.producer,
            "manifest_version": self.manifest_version,
            "producer_schema_version": self.producer_schema_version,
            "tool_count": len(self.tools),
            "digest": self.digest,
        }

    # ---- loading --------------------------------------------------------

    @classmethod
    def from_obj(cls, obj: Any, digest: str = "") -> CapabilityManifest:
        if not isinstance(obj, dict):
            raise ManifestError("manifest root must be a JSON object")
        tools_raw = obj.get("tools")
        if not isinstance(tools_raw, dict):
            raise ManifestError("manifest must carry a 'tools' object")

        tools: dict[str, Capability] = {}
        for tool_id, spec in tools_raw.items():
            if not isinstance(tool_id, str) or not tool_id:
                raise ManifestError(f"tool id must be a non-empty string: {tool_id!r}")
            if not isinstance(spec, dict):
                raise ManifestError(f"tool {tool_id!r} must map to an object")
            effects = spec.get("effects")
            if not isinstance(effects, list) or not effects:
                raise ManifestError(f"tool {tool_id!r} must declare a non-empty "
                                    "'effects' list")
            bad = [e for e in effects if e not in VALID_EFFECTS]
            if bad:
                raise ManifestError(
                    f"tool {tool_id!r} declares unknown effect(s) {bad!r}; "
                    f"valid effects are {sorted(VALID_EFFECTS)}")
            rev = spec.get("reversible")
            if rev is not None and not isinstance(rev, bool):
                raise ManifestError(f"tool {tool_id!r} 'reversible' must be a boolean")
            dest = spec.get("destination")
            if dest is not None and not isinstance(dest, str):
                raise ManifestError(f"tool {tool_id!r} 'destination' must be a string")
            sensitive = spec.get("sensitive_args") or []
            if not isinstance(sensitive, list) or any(
                    not isinstance(s, str) for s in sensitive):
                raise ManifestError(
                    f"tool {tool_id!r} 'sensitive_args' must be a list of strings")
            tools[tool_id] = Capability(
                tool_id=tool_id,
                effects=frozenset(effects),
                reversible=rev,
                destination=dest,
                requires_approval=bool(spec.get("requires_approval", False)),
                sensitive_args=tuple(sensitive),
            )

        return cls(
            producer=str(obj.get("producer", "")),
            manifest_version=str(obj.get("manifest_version", "")),
            producer_schema_version=str(obj.get("producer_schema_version", "")),
            tools=tools,
            digest=digest,
        )

    @classmethod
    def from_file(cls, path: str | Path) -> CapabilityManifest:
        p = Path(path)
        blob = p.read_bytes()
        try:
            obj = json.loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestError(f"{p}: not readable as UTF-8 JSON: {exc}") from exc
        return cls.from_obj(obj, digest=hashlib.sha256(blob).hexdigest()[:16])


EMPTY_MANIFEST = CapabilityManifest()
