# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Mac Descendant of an Office Application
# RTA: mac_office_descendant.py
# Description: Creates a suspicious process spawned from "Microsoft Word"

import logging
from pathlib import Path

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="bb523eb1-db67-4ae6-9369-af1a93322817",
    name="mac_office_descendant",
    platforms=[OSType.MACOS],
)
def main():
    log.info("Emulating Microsoft Word running enumeration commands")
    office_path = Path("Microsoft Word").resolve()
    _common.copy_file("/bin/sh", office_path)

    _ = _common.execute_command([str(office_path)], stdin_data="whoami")

    _common.remove_files([office_path])
