# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="f2e5c332-ad54-4bfa-8d51-ce1a85e749d7",
    name="exec_cmd_wmi_cmdexe",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="12f07955-1674-44f7-86b5-c35da0a6f41a", name="Suspicious Cmd Execution via WMI")],
    techniques=["T1047"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    wmiprvse = "C:\\Users\\Public\\wmiprvse.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    _common.copy_file(EXE_FILE, wmiprvse)

    # Execute command
    _common.execute([wmiprvse, "/c", cmd, "/c", "echo", "\\\\127.0.0.1\\", "'1>'"], timeout=5)
    _common.remove_file(wmiprvse)
