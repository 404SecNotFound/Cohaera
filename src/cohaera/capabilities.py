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

SIGNING THE MANIFEST LIVES OUTSIDE THIS MODULE, AND NOW EXISTS
    This file used to say the manifest was unsigned because signing needed a key
    distribution story that did not exist. That story is now
    ``cohaera.trust_store:1`` (see :mod:`cohaera.evidence`), so the manifest can
    be attested with a detached ``cohaera.policy_signature:1`` over its exact
    bytes, verified against a key the operator gave the ``policy`` role.

    The signature is deliberately NOT a field in this file, and it is not parsed
    here. Two reasons, and both are the same reason in different clothes. A
    signature embedded in the document it signs has to be excised before hashing,
    which is a canonicalisation problem and canonicalisation problems are where
    signature bugs live. And a manifest parser that verified its own signature
    would be checking a claim against a key chosen by the same call that supplied
    the claim; the check belongs to the caller, which is why ``cli`` does it and
    refuses to score when it fails.

    Signing is OPTIONAL and its absence is REPORTED. Every verdict carries a
    ``policy_attestations`` entry saying ``POLICY_SIGNATURE_ABSENT`` when nothing
    was supplied, because an unsigned manifest that says so is a different
    artifact from one that passes in silence.

The digests below are unchanged and still do their own job: recorded in every
verdict, so that two runs disagreeing about what a tool does are distinguishable
after the fact whether or not anybody signed anything.

TWO DIGESTS, NOT ONE (C4-10)
    The recorded digest used to be a hash of the file's bytes alone, so
    re-indenting the JSON or reordering its keys changed it and every verdict
    after the edit looked like it had run under a different policy. The fourth
    review proposed replacing it with a hash of the parsed semantics. That trade
    goes the wrong way on its own: a semantic digest reports *no change* for an
    edit that adds a field this parser does not yet read, and "did the policy
    file change at all" is exactly the question a tamper signal has to answer
    strictly.

    So both ship, and they answer different questions:

        file_digest      sha256 of the exact bytes read from disk. The tamper
                         signal. Moves for any edit, including ones Cohaera
                         cannot interpret.
        semantic_digest  sha256 of the parsed capability records -- every field
                         Cohaera acts on, normalised and canonically ordered.
                         Moves only when the meaning changes.

    The pair is worth more than either alone, because the *gap* between them is
    itself a reading. Same semantic digest, different file digest: a reformat,
    or an edit in a part of the file this version does not parse. Different
    semantic digest: the policy changed, and every verdict on either side of the
    change is answering a different question.

    ``semantic_digest`` deliberately excludes ``producer``, ``manifest_version``
    and ``producer_schema_version``. Those are labels travelling with the
    verdict, not inputs to any classification, and folding them in would make a
    version bump indistinguishable from a capability change -- which is the
    failure the semantic digest exists to avoid.
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

# Tagged into the semantic digest so the digest commits to the SET OF FIELDS it
# covers, not just their values. When a later version starts parsing a field it
# ignores today, that field joins the semantics; bumping this tag makes every
# digest visibly change rather than silently mean something new.
SEMANTICS_SCHEMA = "cohaera.manifest.semantics:2"


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

    def semantics(self) -> dict[str, Any]:
        """This record reduced to what it MEANS, with spelling normalised away.

        Two declarations that Cohaera would act on identically must reduce to
        the same structure here, or the semantic digest is just a slower byte
        digest. Hence: effects sorted (a set, written as a list); sensitive_args
        sorted and de-duplicated (a set of argument names, and naming one twice
        does not make it more sensitive); an empty ``destination`` folded to
        None, because a declared-but-blank destination is an absent one.

        Faithfulness to what the file literally said is ``file_digest``'s job.
        """
        return {
            "effects": sorted(self.effects),
            "reversible": self.reversible,
            "destination": self.destination or None,
            "requires_approval": self.requires_approval,
            "sensitive_args": sorted(set(self.sensitive_args)),
        }


@dataclass(frozen=True)
class PolicyDeclaration:
    """What one guardrail is declared to DO when it fires.

    P1.3 gives the policy engine a place to say ``enforcement`` on the event
    itself, and that field alone would be a mistake to act on. It arrives in
    band, from the same path an attacker controls, and it SUPPRESSES a finding:
    an agent that wanted CH04 quiet would stamp ``advisory`` on a control that
    blocks and never be contradicted. That is SEC-03 exactly -- the producer's
    ``reversible`` flag deciding whether a call is consequential -- reappearing
    on the check that is supposed to catch a bypass.

    So the manifest gets a ``policies`` section, and it outranks the event, for
    the same reason and with the same precedence as ``tools``: the operator
    chose this file, the agent wrote the event. A deployment that declares its
    blocking controls here cannot be talked out of them by the thing being
    watched.

    Keyed on ``policy_id`` where the producer emits one, and on the event type
    otherwise, because observra's ``cost_threshold_exceeded`` and
    ``depth_exceeded`` carry no policy identifier at all.
    """

    policy_id: str
    enforcement: str
    description: str = ""

    def semantics(self) -> dict[str, Any]:
        return {"enforcement": self.enforcement}


# Values a policy may declare. Mirrors cohaera.evidence.VALID_ENFORCEMENT, and
# is spelled out here rather than imported because ``evidence`` imports
# ``identity`` and ``validate``, and nothing on the manifest path needs either.
VALID_ENFORCEMENT = frozenset({"blocking", "advisory"})


@dataclass(frozen=True)
class CapabilityManifest:
    """A producer's declaration of its tool surface."""

    producer: str = ""
    manifest_version: str = ""
    producer_schema_version: str = ""
    tools: dict[str, Capability] = field(default_factory=dict)
    policies: dict[str, PolicyDeclaration] = field(default_factory=dict)
    # See the module docstring. file_digest is the tamper signal and is empty
    # for a manifest built in memory; semantic_digest is defined for every
    # manifest, file-backed or not, because it is computed from the records.
    file_digest: str = ""
    semantic_digest: str = ""

    @property
    def loaded(self) -> bool:
        return bool(self.tools)

    def get(self, tool_id: Any) -> Capability | None:
        if not isinstance(tool_id, str) or not tool_id:
            return None
        return self.tools.get(tool_id)

    def policy(self, *candidates: Any) -> PolicyDeclaration | None:
        """The operator's declaration for a policy, by ``policy_id`` then type.

        Takes the candidates in preference order so the caller does not have to
        care which of them the producer happened to emit.
        """
        for key in candidates:
            if isinstance(key, str) and key:
                found = self.policies.get(key)
                if found is not None:
                    return found
        return None

    def klass_for(self, tool_id: Any) -> str | None:
        cap = self.get(tool_id)
        return cap.klass if cap is not None else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "producer": self.producer,
            "manifest_version": self.manifest_version,
            "producer_schema_version": self.producer_schema_version,
            "tool_count": len(self.tools),
            "policy_count": len(self.policies),
            "file_digest": self.file_digest,
            "semantic_digest": self.semantic_digest,
        }

    # ---- loading --------------------------------------------------------

    @classmethod
    def from_obj(cls, obj: Any, file_digest: str = "",
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

        policies: dict[str, PolicyDeclaration] = {}
        policies_raw = obj.get("policies")
        if policies_raw is not None:
            if not isinstance(policies_raw, dict):
                raise ManifestError("manifest 'policies' must be an object")
            if len(policies_raw) > limits.max_manifest_tools:
                raise ManifestError(
                    f"manifest declares {len(policies_raw)} policies, exceeding "
                    f"max_manifest_tools={limits.max_manifest_tools}")
            for policy_id, spec in policies_raw.items():
                if not isinstance(policy_id, str) or not policy_id:
                    raise ManifestError(
                        f"policy id must be a non-empty string: {policy_id!r}")
                _bounded_str(policy_id, f"policy id {policy_id[:64]!r}")
                if not isinstance(spec, dict):
                    raise ManifestError(f"policy {policy_id!r} must map to an object")
                enforcement = spec.get("enforcement")
                if enforcement not in VALID_ENFORCEMENT:
                    # No default. A policy declared here with no usable
                    # enforcement is the operator saying something Cohaera
                    # cannot act on, and guessing which way they meant it is how
                    # a suppression gets shipped as a feature.
                    raise ManifestError(
                        f"policy {policy_id!r} must declare 'enforcement' as one "
                        f"of {sorted(VALID_ENFORCEMENT)}, got {enforcement!r}")
                description = spec.get("description", "")
                if description != "":
                    description = _bounded_str(
                        description, f"policy {policy_id!r} 'description'")
                policies[policy_id] = PolicyDeclaration(
                    policy_id=policy_id, enforcement=enforcement,
                    description=description)

        # These three are emitted verbatim into every verdict's provenance, so
        # they are bounded too rather than coerced with str(): str({...}) on a
        # dict produced a repr that then travelled to the SIEM as a "producer".
        meta = {}
        for key in ("producer", "manifest_version", "producer_schema_version"):
            value = obj.get(key, "")
            meta[key] = "" if value == "" else _bounded_str(value, f"'{key}'")

        return cls(tools=tools, policies=policies, file_digest=file_digest,
                   semantic_digest=semantic_digest(tools, policies), **meta)

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
        return cls.from_obj(obj, file_digest=hashlib.sha256(blob).hexdigest()[:16],
                            limits=limits)


def semantic_digest(tools: dict[str, Capability],
                    policies: dict[str, PolicyDeclaration] | None = None) -> str:
    """Hash what the manifest MEANS: every parsed field, canonically ordered.

    Deliberately not routed through ``identity.canonical``. Everything hashed
    here has already been through ``from_obj``'s type checks -- strings, bools,
    and members of ``VALID_EFFECTS`` -- so there is no producer-controlled float
    that could arrive as NaN and no structure that needs coercing. Hashing it
    directly also keeps ``capabilities`` free of an import edge to ``identity``,
    which imports ``validate``, which nothing on this path needs.

    An empty manifest hashes to "" rather than to the digest of an empty tool
    map. "No manifest was loaded" and "a manifest was loaded and declared
    nothing" are different states, and only one of them should be reported as a
    policy identity.
    """
    policies = policies or {}
    if not tools and not policies:
        return ""
    payload = {
        "schema": SEMANTICS_SCHEMA,
        "tools": {tool_id: cap.semantics() for tool_id, cap in tools.items()},
        "policies": {pid: p.semantics() for pid, p in policies.items()},
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


EMPTY_MANIFEST = CapabilityManifest()
