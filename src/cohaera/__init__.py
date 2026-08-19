"""Cohaera: the correlation and coherence layer for agent telemetry.

From Latin *cohaerere*, to hang together.

observra captures and normalises agent events. Its rule engine signature is
``evaluate_rules(event_type, data)``: stateless, single-event, cannot see two
events at once. Exabeam issue #108 on that repo records the consequence in the
maintainer's own words: "28/34 AI analytics rules work today. Zero correlation
rules can fire."

Cohaera assembles that flat stream into sessions, derives behavioural features
that only exist once events are grouped, and emits correlation-grade CIM records
that a SIEM can actually write rules against.

It does not replace behavioural analytics. It feeds it.
"""

__version__ = "0.3.0"

from .capabilities import Capability, CapabilityManifest, ManifestError
from .checks import SequenceGrammar, coverage, run_all
from .identity import CorrelationKey, Correlator
from .ingest import assemble, load, read_events
from .limits import DEFAULT_LIMITS, Limits
from .model import Event, Finding, Session, ToolCall, to_cim_event
from .validate import IngestReport, RecordView, Reject, sanitise_display

__all__ = [
    "DEFAULT_LIMITS",
    "Capability",
    "CapabilityManifest",
    "CorrelationKey",
    "Correlator",
    "Event",
    "Finding",
    "IngestReport",
    "Limits",
    "ManifestError",
    "RecordView",
    "Reject",
    "SequenceGrammar",
    "Session",
    "ToolCall",
    "__version__",
    "assemble",
    "coverage",
    "load",
    "read_events",
    "run_all",
    "sanitise_display",
    "to_cim_event",
]
