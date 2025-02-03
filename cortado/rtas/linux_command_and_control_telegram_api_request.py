# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="ceab22a5-35d6-47e0-9658-d0405fea72fa",
    name="linux_command_and_control_telegram_api_request",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="87bee79f-cf0b-43a0-884a-a7a4ddbd4599", name="Linux Telegram API Request"),
    ],
    techniques=["T1071"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/curl"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "api.telegram.org"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
