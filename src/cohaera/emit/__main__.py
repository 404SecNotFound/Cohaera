# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""``python -m cohaera.emit``: the same commands as ``cohaera keygen | sign |
issue-approval``, kept for collectors that invoke the module directly."""

from .command import main

raise SystemExit(main())
