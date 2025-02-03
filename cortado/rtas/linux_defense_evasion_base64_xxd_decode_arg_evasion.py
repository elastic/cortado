# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="20b06a60-46da-4a27-8e72-df8bf0de37ad",
    name="linux_defense_evasion_base64_xxd_decode_arg_evasion",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="789f8a41-00cb-40cb-b41f-c2e1611b1245", name="Base64 or Xxd Decode Argument Evasion"),
    ],
    techniques=["T1027", "T1140", "T1059", "T1204"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/xxd"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "-pevil ", "-revil "]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
