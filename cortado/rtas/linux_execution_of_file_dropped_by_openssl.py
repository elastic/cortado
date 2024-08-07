# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType

import time


@register_code_rta(
    id="f9a0601a-4c36-41df-bdf6-140ae7c99de3",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="7032dd32-8a51-4545-94d0-5997051f4610", name="Linux Execution of a File Dropped by OpenSSL")
    ],
    techniques=["T1027", "T1140", "T1204"],
)
def main():
    masquerade = "/dev/shm/evil"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    commands = [masquerade, "/dev/shm/evil"]

    masquerade_file = "/tmp/openssl"
    source = _common.get_path("bin", "create_file.elf")
    _common.copy_file(source, masquerade_file)

    _common.log("Granting execute permissions...")
    _common.execute(["chmod", "+x", masquerade_file])

    commands_file = [masquerade_file, "/dev/shm/evil"]

    _common.log("Simulating file creation activity..")
    _common.execute([*commands_file], timeout=5)
    _common.log("File creation simulation successful!")
    time.sleep(1)

    _common.remove_file(masquerade_file)

    _common.copy_file(source, masquerade)
    _common.log("Launching fake command to simulate OpenSSL execution")
    _common.execute([*commands], timeout=5, kill=True)

    _common.log("Cleaning...")
    _common.remove_file(masquerade)
    _common.log("RTA completed!")
