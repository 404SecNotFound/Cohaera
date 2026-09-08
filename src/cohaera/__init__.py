"""Passive security monitoring and detection engineering for agent telemetry.

From Latin *cohaerere*, to hang together.

Cohaera reads exported events out of band, assembles them into sessions, checks
the evidence, derives security features, and emits records and detections for a
SIEM or investigation workflow. It does not proxy, authorize, or block agent
actions.
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
