# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="6294e8bd-a82e-4d60-9de7-cceb639e91d9",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="e390d36d-c739-43ee-9e3d-5a76fa853bd5", name="Suspicious Automator Workflows Execution")
    ],
    siem_rules=[
        RuleMetadata(id="5d9f8cfc-0d03-443e-a167-2b0597ce0965", name="Suspicious Automator Workflows Execution")
    ],
    techniques=["T1059"],
)
def main():
    # create masquerades
    masquerade = "/tmp/automator"
    masquerade2 = "/tmp/com.apple.automator.runner"
    _common.create_macos_masquerade(masquerade)
    _common.copy_file("/usr/bin/curl", masquerade2)

    # Execute command
    _common.log("Launching fake commands to launch Automator workflows")
    _common.execute([masquerade], timeout=10, kill=True)
    _common.execute([masquerade2, "portquiz.net"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)


