# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="33f3ebda-7776-4cec-933b-48e85d707d61",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {
            "rule_name": "Suspicious Process Spawned from MOTD Detected",
            "rule_id": "b9b3922a-59ee-407c-8773-31b98bf9b18d",
        }
    ],
    siem_rules=[
        {
            "rule_name": "Suspicious Process Spawned from MOTD Detected",
            "rule_id": "4ec47004-b34a-42e6-8003-376a123ea447",
        }
    ],
    techniques=[""],
)
def main():
    _common.log("Creating a fake MOTD executable..")
    masquerade = "/etc/update-motd.d/evil"
    source = _common.get_path("bin", "netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)

    _common.log("Granting execute permissions...")
    _common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "netcat"]

    _common.log("Simulating MOTD netcat activity..")
    _common.execute([*commands], timeout=5)
    _common.log("MOTD netcat simulation successful!")
    _common.log("Cleaning...")
    _common.remove_file(masquerade)
    _common.log("RTA completed!")


