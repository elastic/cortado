# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Export Registry Hives
# RTA: registry_hive_export.py
# ATT&CK: TBD
# Description: Exports the SAM, SECURITY and SYSTEM hives - useful in credential harvesting and discovery attacks.

from pathlib import Path


REG = "reg.exe"


@register_code_rta(
    id="dfdcc4f4-5aca-486a-8115-b15b653b9b4f",
    name="registry_hive_export",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="a7e7bfa3-088e-4f13-b29e-3986e0e756b8", name="Credential Acquisition via Registry Hive Dumping")
    ],
    techniques=["T1003"],
)
def main():
    for hive in ["sam", "security", "system"]:
        filename = Path("%s.reg" % hive).resolve()
        _common.log("Exporting %s hive to %s" % (hive, filename))
        _common.execute([REG, "save", "hkey_local_machine\\%s" % hive, filename])
        _common.remove_file(filename)

        _common.execute([REG, "save", "hklm\\%s" % hive, filename])
        _common.remove_file(filename)
