# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="1048ff54-4ac4-441f-839d-e4d06a0cb211",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="eb78fa0f-5e8a-4c15-a099-e904c4a226e6", name="Potential WizardUpdate Malware Infection")
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    masquerade = "/tmp/curl"
    _common.create_macos_masquerade(masquerade)

    # Execute commands
    _common.log("Launching fake curl commands to mimic WizardUpdate infection")
    _common.execute([masquerade, "test_intermediate_agent_testmachine_idtest"], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
