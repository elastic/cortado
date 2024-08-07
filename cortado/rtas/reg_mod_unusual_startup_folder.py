# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="4ac771ca-5095-4a1b-ac6a-e2b714be8ccc",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="377aad38-24e0-4dd7-93c2-bd231cb749e3", name="Unusual Startup Shell Folder Modification")
    ],
    siem_rules=[],
    techniques=["T1547", "T1547.001", "T1112"],
)
def main():
    _common.log("Temp Registry mod: Common Startup Folder")

    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
    value = "Common Startup"
    data = "Test"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
