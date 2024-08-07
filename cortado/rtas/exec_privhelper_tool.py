# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import _common


@register_code_rta(
    id="aac863d1-8306-463e-b81f-3d97ba925a44",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        {
            "rule_name": "Suspicious PrivilegedHelperTool Activity",
            "rule_id": "900fdb84-2a81-4a6d-88db-b48a0fafd79e",
        }
    ],
    siem_rules=[],
    techniques=["T1068"],
)
def main():
    tools = Path("/Library/PrivilegedHelperTools")
    tools.mkdir(parents=True, exist_ok=True)
    masquerade = str(tools / "testbin")
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake bash commands to abnormal echo shell commands")
    command = f"bash -c '/tmp/*'"
    _common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)

    # cleanup
    _common.remove_directory(str(tools))


