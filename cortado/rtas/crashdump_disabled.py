# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="775ffaa8-7a44-490b-b13d-1bfa2100b1ae",
    name="crashdump_disabled",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="77ca3fcc-f607-45e0-837e-e4173e4ffc2a", name="CrashDump Disabled via Registry Modification")
    ],
    siem_rules=[],
    techniques=["T1112"],
)
def main():
    _common.log("Temporarily disabling CrashDump...")

    key = "System\\CurrentControlSet\\Control\\CrashControl"
    value = "CrashDumpEnabled"
    data = "0"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
