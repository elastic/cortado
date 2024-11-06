# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b3c8c616-15a5-45fd-970a-c44c18e59578",
    name="linux_command_and_control_curl_wget_hidden_directory_output",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="dc1cee03-4923-4c6b-b00b-8a5c323bb753", name="File Downloaded via Curl or Wget to Hidden Directory"
        ),
    ],
    techniques=["T1564"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/curl"

    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "--output", "/dev/shm/evil"]
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
