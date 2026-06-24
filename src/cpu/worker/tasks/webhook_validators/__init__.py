# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 CPU contributors
"""
CPU bot webhook validators package.

Importing this package causes all built-in platform validators to
self-register in WEBHOOK_VALIDATORS (defined in .base).

To add a new hosting platform: create a new module that appends its
validator class to WEBHOOK_VALIDATORS at import time, then add a
corresponding import below.
"""

# Import platform modules to trigger their self-registration in WEBHOOK_VALIDATORS.
from cpu.worker.tasks.webhook_validators import github as _github_module  # noqa: F401
from cpu.worker.tasks.webhook_validators import gitlab as _gitlab_module  # noqa: F401
