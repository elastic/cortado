# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="d2bc8d23-736f-4045-87cd-81d9f4719d2f",
    name="reg_mod_point_and_print_dll",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="bd7eefee-f671-494e-98df-f01daf9e5f17", name="Suspicious Print Spooler Point and Print DLL")
    ],
    techniques=["T1068"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\RTA"
    value = "SpoolDirectory"
    data = "C:\\Windows\\System32\\spool\\drivers\\x64\\4"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass

    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\RTA\\CopyFiles\\Payload"
    value = "Module"
    data = "C:\\Windows\\System32\\spool\\drivers\\x64\\4\\RTA.dll"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
