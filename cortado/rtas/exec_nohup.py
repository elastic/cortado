# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="b2faa842-ffc9-41c6-baed-8008c9749a52",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_name": "Suspicious Nohup Execution",
            "rule_id": "3f18726c-4897-41dc-8426-15da95b8482f",
        }
    ],
    techniques=["T1059", "T1059.004", "T1564", "T1564.003"],
)
def main():
    test_file = "/tmp/test.txt"
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    command = f"nohup {test_file}"
    _common.log("Launching bash commands to mimic suspicious nohup execution")
    with _common.temporary_file("testing", test_file):
        _common.execute([masquerade, "childprocess", command, "&"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


