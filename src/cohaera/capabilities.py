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

from .limits import DEFAULT_LIMITS, Limits

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
    def from_obj(cls, obj: Any, digest: str = "",
                 limits: Limits = DEFAULT_LIMITS) -> CapabilityManifest:
        if not isinstance(obj, dict):
            raise ManifestError("manifest root must be a JSON object")
        tools_raw = obj.get("tools")
        if not isinstance(tools_raw, dict):
            raise ManifestError("manifest must carry a 'tools' object")
        if len(tools_raw) > limits.max_manifest_tools:
            raise ManifestError(
                f"manifest declares {len(tools_raw)} tools, exceeding "
                f"max_manifest_tools={limits.max_manifest_tools}")

        def _bounded_str(value: Any, what: str) -> str:
            if not isinstance(value, str) or isinstance(value, bool):
                raise ManifestError(f"{what} must be a string, got "
                                    f"{type(value).__name__}")
            if len(value) > limits.max_manifest_field_chars:
                raise ManifestError(
                    f"{what} is {len(value)} chars, exceeding "
                    f"max_manifest_field_chars={limits.max_manifest_field_chars}")
            return value

        tools: dict[str, Capability] = {}
        for tool_id, spec in tools_raw.items():
            if not isinstance(tool_id, str) or not tool_id:
                raise ManifestError(f"tool id must be a non-empty string: {tool_id!r}")
            _bounded_str(tool_id, f"tool id {tool_id[:64]!r}")
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
            if dest is not None:
                dest = _bounded_str(dest, f"tool {tool_id!r} 'destination'")
            # C4-06. This was ``bool(spec.get("requires_approval", False))``, so
            # the JSON string "false" -- which is what a producer emits when its
            # serialiser stringifies booleans, and what an attacker writes on
            # purpose -- became True. Truthiness is not a schema. Every other
            # field on this record is type-checked; this one silently guessed,
            # and it guesses in the direction that changes a verdict.
            approval = spec.get("requires_approval", False)
            if not isinstance(approval, bool):
                raise ManifestError(
                    f"tool {tool_id!r} 'requires_approval' must be a boolean, got "
                    f"{type(approval).__name__} {approval!r}")
            sensitive = spec.get("sensitive_args") or []
            if not isinstance(sensitive, list) or any(
                    not isinstance(s, str) for s in sensitive):
                raise ManifestError(
                    f"tool {tool_id!r} 'sensitive_args' must be a list of strings")
            if len(sensitive) > limits.max_manifest_sensitive_args:
                raise ManifestError(
                    f"tool {tool_id!r} declares {len(sensitive)} sensitive_args, "
                    f"exceeding max_manifest_sensitive_args="
                    f"{limits.max_manifest_sensitive_args}")
            for s in sensitive:
                _bounded_str(s, f"tool {tool_id!r} sensitive_arg")
            tools[tool_id] = Capability(
                tool_id=tool_id,
                effects=frozenset(effects),
                reversible=rev,
                destination=dest,
                requires_approval=approval,
                sensitive_args=tuple(sensitive),
            )

        # These three are emitted verbatim into every verdict's provenance, so
        # they are bounded too rather than coerced with str(): str({...}) on a
        # dict produced a repr that then travelled to the SIEM as a "producer".
        meta = {}
        for key in ("producer", "manifest_version", "producer_schema_version"):
            value = obj.get(key, "")
            meta[key] = "" if value == "" else _bounded_str(value, f"'{key}'")

        return cls(tools=tools, digest=digest, **meta)

    @classmethod
    def from_file(cls, path: str | Path,
                  limits: Limits = DEFAULT_LIMITS) -> CapabilityManifest:
        p = Path(path)
        # Read one byte past the bound rather than stat()-ing: a FIFO or a
        # /proc file reports a size of zero and then streams forever, and the
        # point of a byte bound is that it holds for input chosen to defeat it.
        with p.open("rb") as fh:
            blob = fh.read(limits.max_manifest_bytes + 1)
        if len(blob) > limits.max_manifest_bytes:
            raise ManifestError(
                f"{p}: manifest exceeds max_manifest_bytes="
                f"{limits.max_manifest_bytes}")
        try:
            obj = json.loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestError(f"{p}: not readable as UTF-8 JSON: {exc}") from exc
        except RecursionError as exc:                  # deeply nested manifest
            raise ManifestError(f"{p}: nesting too deep to parse") from exc
        return cls.from_obj(obj, digest=hashlib.sha256(blob).hexdigest()[:16],
                            limits=limits)


EMPTY_MANIFEST = CapabilityManifest()
