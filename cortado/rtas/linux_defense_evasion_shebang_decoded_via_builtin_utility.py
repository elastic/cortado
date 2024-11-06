# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="074901e7-118b-4536-bbed-0e57c319ba2a",
    name="linux_defense_evasion_shebang_decoded_via_builtin_utility",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="e659b4b9-5bbf-4839-96b9-b489334b4ca1", name="Base64 Shebang Payload Decoded via Built-in Utility"
        ),
    ],
    techniques=["T1027", "T1140", "T1059", "T1204"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/base64"

    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "-d", "IyEvdXNyL2Jpbi9weXRob24"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
