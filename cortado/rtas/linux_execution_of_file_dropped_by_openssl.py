# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)



@register_code_rta(
    id="f9a0601a-4c36-41df-bdf6-140ae7c99de3",
    name="linux_execution_of_file_dropped_by_openssl",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="7032dd32-8a51-4545-94d0-5997051f4610", name="Linux Execution of a File Dropped by OpenSSL")
    ],
    techniques=["T1027", "T1140", "T1204"],
)
def main():
    masquerade = "/dev/shm/evil"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    commands = [masquerade, "/dev/shm/evil"]

    masquerade_file = "/tmp/openssl"
    source = _common.get_path("bin", "create_file.elf")
    _common.copy_file(source, masquerade_file)

    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade_file])

    commands_file = [masquerade_file, "/dev/shm/evil"]

    log.info("Simulating file creation activity..")
    _ = _common.execute_command([*commands_file], timeout_secs=5)
    log.info("File creation simulation successful!")
    time.sleep(1)

    _common.remove_file(masquerade_file)

    _common.copy_file(source, masquerade)
    log.info("Launching fake command to simulate OpenSSL execution")
    _ = _common.execute_command([*commands], timeout_secs=5)

    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("RTA completed!")
