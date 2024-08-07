# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="1a483c55-443d-4d01-a9de-e2c69df744f3",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        {
            "rule_name": "Initial Access or Execution via Microsoft Office Application",
            "rule_id": "64021ef9-19d3-4797-ac3c-79e38d5e5a5a",
        }
    ],
    siem_rules=[],
    techniques=["T1105", "T1140", "T1027", "T1566", "T1547", "T1204", "T1059"],
)
def main():
    masquerade = "/tmp/Microsoft PowerPoint"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake Microsoft Office process")
    _common.execute([masquerade], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
