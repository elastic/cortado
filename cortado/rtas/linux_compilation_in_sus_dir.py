# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="15043951-ca9b-4fbe-b3cb-d1288a875ca7",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="52001df2-a3bf-411d-a09c-5f36a9f976b8", name="Linux Compilation in Suspicious Directory")
    ],
    techniques=["T1027"],
)
def main():
    masquerade = "/tmp/gcc"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "evil"]

    masquerade_file = "/tmp/ld"
    source = _common.get_path("bin", "create_file.elf")
    _common.copy_file(source, masquerade_file)

    _common.log("Granting execute permissions...")
    _common.execute(["chmod", "+x", masquerade_file])

    commands_file = [masquerade_file, "/dev/shm/evil"]

    # Execute command
    _common.log("Launching fake command to simulate file compilation")
    _common.execute([*commands], timeout=5, kill=True)

    _common.log("Simulating file creation activity..")
    _common.execute([*commands_file], timeout=5)
    _common.log("File creation simulation successful!")
    _common.log("Cleaning...")
    _common.remove_file(masquerade_file)
    _common.log("RTA completed!")
