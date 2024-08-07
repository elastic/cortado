# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="d00ef4d9-4690-4eb1-aa60-7ff3ce3bd75b",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="f24bcae1-8980-4b30-b5dd-f851b055c9e7", name="Creation of Hidden Login Item via Apple Script")
    ],
    techniques=["T1547", "T1059"],
)
def main():
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake osascript commands to mimic hidden file creation")
    _common.execute(
        [masquerade, "childprocess", "osascript login item hidden:true"],
        shell=True,
        timeout=5,
        kill=True,
    )

    # cleanup
    _common.remove_file(masquerade)
