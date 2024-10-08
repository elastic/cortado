# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="94366604-8f84-448e-9761-0eb7b45bc2fa",
    name="linux_exec_interactive_shell",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="aa02591f-c9e6-4317-841e-0b075b9515ff",
            name="Linux Suspicious Child Process Execution via Interactive Shell",
        ),
    ],
    techniques=["T1059"],
)
def main() -> None:
    masquerade = "/tmp/bash"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    commands = [masquerade, "-i"]

    # Execute command
    log.info("Launching fake command to simulate an interactive shell process")
    _ = _common.execute_command(commands, timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
