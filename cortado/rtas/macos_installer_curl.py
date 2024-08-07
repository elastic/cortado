# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="34040af5-1231-4e97-8189-a26d6622b2e5",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="d40ffcba-b83e-4d0a-8d6d-84385def8e18", name="Initial Access via macOS Installer Package")
    ],
    siem_rules=[],
    techniques=["T1105", "T1543", "T1082", "T1566", "T1204", "T1547", "T1569", "T1059"],
)
def main():
    # create masquerades
    masquerade = "/tmp/Installer"
    masquerade2 = "/tmp/curl"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)

    # Execute command
    _common.log("Launching fake macOS installer commands to download payload")
    _common.execute([masquerade], timeout=10, kill=True)

    command = f"{masquerade2} test.amazonaws.comtest "
    _common.execute([masquerade, "childprocess", command], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)


