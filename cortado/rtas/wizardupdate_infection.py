# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1048ff54-4ac4-441f-839d-e4d06a0cb211",
    name="wizardupdate_infection",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="eb78fa0f-5e8a-4c15-a099-e904c4a226e6", name="Potential WizardUpdate Malware Infection")
    ],
)
def main():
    masquerade = "/tmp/curl"
    _common.create_macos_masquerade(masquerade)

    # Execute commands
    log.info("Launching fake curl commands to mimic WizardUpdate infection")
    _ = _common.execute_command([masquerade, "test_intermediate_agent_testmachine_idtest"], timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
