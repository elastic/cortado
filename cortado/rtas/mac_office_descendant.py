# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Mac Descendant of an Office Application
# RTA: mac_office_descendant.py
# Description: Creates a suspicious process spawned from "Microsoft Word"

from pathlib import Path

from . import _common, register_code_rta, OSType


@register_code_rta(
    id="bb523eb1-db67-4ae6-9369-af1a93322817",
    name="mac_office_descendant",
    platforms=[OSType.MACOS],
)
def main():
    _common.log("Emulating Microsoft Word running enumeration commands")
    office_path = Path("Microsoft Word").resolve()
    _common.copy_file("/bin/sh", office_path)

    _common.execute([office_path], stdin="whoami")

    _common.remove_files(office_path)
