# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


EXE_FILE = "bin/renamed_posh.exe"


@register_code_rta(
    id="32faebaa-b581-464c-bca9-6936fe0948dc",
    name="exec_shortcut_embedded_obj",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="8076640d-ec66-4d24-a252-ee2f054e00a1", name="Windows Shortcut File Embedded Object Execution"),
        RuleMetadata(id="9fdd772b-b483-404f-bc02-7ec87e332bec", name="Embedded Executable via Windows Shortcut File"),
    ],
    techniques=["T1059", "T1059.003", "T1204", "T1204.001", "T1204.002", "T1566", "T1566.001", "T1566.002"],
)
def main():
    cmd = "C:\\Users\\Public\\cmd.exe"
    rta = "C:\\Users\\Public\\rta.exe"
    tempfile = "C:\\Users\\Public\\a.txt"
    _common.copy_file(EXE_FILE, cmd)
    _common.copy_file(EXE_FILE, rta)

    # Execute command
    _ = _common.execute_command(
        [cmd, "/c", f"Copy-Item {EXE_FILE} '{tempfile}'; echo 'finda.a.lnk >1&'; {rta}"], timeout_secs=10
    )
    _common.remove_files([cmd, rta, tempfile])
