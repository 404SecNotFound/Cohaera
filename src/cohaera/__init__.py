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

__version__ = "0.1.0"

from .checks import SequenceGrammar, run_all
from .ingest import assemble, load, read_events
from .model import Event, Finding, Session, ToolCall, to_cim_event

__all__ = [
    "__version__",
    "Event", "Session", "ToolCall", "Finding",
    "read_events", "assemble", "load",
    "SequenceGrammar", "run_all", "to_cim_event",
]
