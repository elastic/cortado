# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="a86199f3-b08c-4fb5-ba92-a706a24090da",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_id": "340bdcad-187f-4ccb-b84e-34ee70844d78",
            "rule_name": "DLL Control Panel Items Registry Modification",
        }
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    _common.log("Temporarily creating a CPL reg key...")

    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\CPLs"
    value = "Test"
    data = "Test"

    with _common.temporary_reg(_common.HKCU, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
