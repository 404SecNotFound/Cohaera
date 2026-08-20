"""External-corpus validation harness.

Cohaera's evaluation runs on a synthetic corpus written by the detector's own
author. That is the single largest weakness in the project and it is stated as
such in the evaluation card. This package is the machinery for closing it:
adapters that map public agent-trace corpora into Cohaera's Session model, a
runner that scores them, and a scope statement -- in :mod:`eval.external.scope`,
enforced by ``tests/test_external.py`` -- saying which of the seven checks that
route can and cannot reach.

The short answer is three of seven, and see docs/EXTERNAL-VALIDATION.md for why.
"""
