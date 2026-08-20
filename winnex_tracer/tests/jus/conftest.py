"""Pytest configuration — sets up paths and env for Tracer-JUS tests.

The Tracer-JUS repo root is inserted FIRST so `core` resolves to Tracer-JUS's
own core; the Tracer-GOV repo is inserted AFTER it so `persistence` and
`compliance` resolve to Tracer-GOV's.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, tempfile

# Repo roots
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TRACER_GOV = os.environ.get("TRACER_GOV_PATH",
                            os.path.abspath(os.path.join(REPO, "..", "tracer-gov")))

# Tracer-JUS must resolve `core` to ITS OWN core, while `persistence` and
# `compliance` must resolve to Tracer-GOV's. Order matters:
#   sys.path[0] = TRACER_GOV  (so its persistence/compliance win)
#   sys.path[1] = REPO        (Tracer-JUS core wins for `core`? NO — see below)
#
# The correct approach: TRACER_JUS repo must be position 0 for `core`, but
# Tracer-GOV must provide `persistence`/`compliance`. Because both packages
# define `core`, we cannot have both. We resolve this by putting Tracer-JUS
# at position 0 (its own `core`, `api`, `tests`) and importing Tracer-GOV's
# `persistence`/`compliance` by absolute path inside Tracer-JUS code (which
# `core/evidence.py` and `compliance/*` already do via sys.path).
for _p in (TRACER_GOV, REPO):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# Isolated evidence path per test session
_EVID = tempfile.mkdtemp(prefix="tracer-jus-test-")
os.environ["TRACER_JUS_EVIDENCE_PATH"] = _EVID
os.environ.setdefault("WINNEX_TRACER_AUDIT_LOG_PATH", _EVID)
