"""Pytest configuration — sets up paths and env for Tracer-MED tests.

Tracer-MED repo first (its own `core`), then Tracer-GOV (provides
`persistence`/`compliance`). Do NOT insert paths in test modules.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TRACER_GOV = os.environ.get("TRACER_GOV_PATH",
                            os.path.abspath(os.path.join(REPO, "..", "tracer-gov")))

for _p in (TRACER_GOV, REPO):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

_EVID = tempfile.mkdtemp(prefix="tracer-med-test-")
os.environ["TRACER_MED_EVIDENCE_PATH"] = _EVID
os.environ.setdefault("WINNEX_TRACER_AUDIT_LOG_PATH", _EVID)
