# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="522a18d6-0c27-499f-86d9-cd421129a38d",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        {
            "rule_name": "Suspicious Property List File Creation or Modification",
            "rule_id": "901f0c30-a7c5-40a5-80e3-a50c6714432f",
        }
    ],
    siem_rules=[],
    techniques=["T1547", "T1543"],
)
def main():
    masquerade = "/tmp/plistbuddy"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake plistbuddy command to modify plist files")
    _common.execute([masquerade, "testRunAtLoad testLaunchAgentstest"], timeout=10, kill=True)
    _common.execute([masquerade, "testProgramArgumentstest"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


