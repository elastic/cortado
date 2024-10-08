# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4c02d7e0-51c3-4fff-ae90-4b560f497c94",
    name="linux_powershell_sus_child_process",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="e9731cea-c3fc-4183-a76c-9a798ae0a2b0", name="Linux Powershell Suspicious Child Process")
    ],
    techniques=["T1059"],
)
def main():
    # Path for the fake pwsh script
    fake_pwsh_script = "/tmp/pwsh"

    # Create fake nc executable
    masquerade = "/tmp/nc"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake pwsh script that launches nc
    with open(fake_pwsh_script, "w") as script:
        _ = script.write("#!/bin/bash\n")
        _ = script.write("/tmp/nc\n")

    # Make the script executable
    _ = _common.execute_command(["chmod", "+x", fake_pwsh_script])

    # Execute the fake pwsh script
    log.info("Launching nc as a child of fake pwsh")
    _ = _common.execute_command([fake_pwsh_script], timeout_secs=5)

    # Cleanup
    _common.remove_file(fake_pwsh_script)
