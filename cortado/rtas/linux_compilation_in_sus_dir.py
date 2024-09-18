# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="15043951-ca9b-4fbe-b3cb-d1288a875ca7",
    name="linux_compilation_in_sus_dir",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="52001df2-a3bf-411d-a09c-5f36a9f976b8", name="Linux Compilation in Suspicious Directory")
    ],
    techniques=["T1027"],
)
def main():
    masquerade = "/tmp/gcc"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "evil"]

    masquerade_file = "/tmp/ld"
    source = _common.get_path("bin", "create_file.elf")
    _common.copy_file(source, masquerade_file)

    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade_file])

    commands_file = [masquerade_file, "/dev/shm/evil"]

    # Execute command
    log.info("Launching fake command to simulate file compilation")
    _ = _common.execute_command([*commands], timeout_secs=5, kill=True)

    log.info("Simulating file creation activity..")
    _ = _common.execute_command([*commands_file], timeout_secs=5)
    log.info("File creation simulation successful!")
    log.info("Cleaning...")
    _common.remove_file(masquerade_file)
    log.info("RTA completed!")
