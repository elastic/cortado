# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="ac6b2cda-97f1-4095-b5f1-9791da2e6282",
    name="reg_mod_lsa_ssp",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="e86da94d-e54b-4fb5-b96c-cecff87e8787", name="Installation of Security Support Provider"),
        RuleMetadata(id="e9abe69b-1deb-4e19-ac4a-5d5ac00f72eb", name="Potential LSA Authentication Package Abuse"),
    ],
    techniques=["T1547", "T1547.002", "T1547.005"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    key = "SYSTEM\\ControlSet001\\Control\\Lsa\\Security Packages"
    key2 = "SYSTEM\\ControlSet001\\Control\\Lsa"
    value = "RTA"
    value2 = "Authentication Packages"
    data = "RTA"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
    with _common.temporary_reg(_common.HKLM, key2, value2, data):
        pass
