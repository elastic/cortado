# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="dd39e94e-bfd7-467c-b20d-662d84c0b97e",
    name="security_authtrampoline",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="f0eb70e9-71e9-40cd-813f-bf8e8c812cb1", name="Execution with Explicit Credentials via Scripting"
        )
    ],
    techniques=["T1078", "T1548", "T1059"],
)
def main():
    # create masquerades
    masquerade = "/tmp/security_authtrampoline"
    _common.create_macos_masquerade(masquerade)

    # Execute commands
    _common.log("Launching fake security_authtrampoline process commands to mimic root execution.")
    _common.execute([masquerade], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
