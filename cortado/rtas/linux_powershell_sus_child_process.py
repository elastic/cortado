# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


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
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake pwsh script that launches nc
    with open(fake_pwsh_script, "w") as script:
        script.write("#!/bin/bash\n")
        script.write("/tmp/nc\n")

    # Make the script executable
    _common.execute(["chmod", "+x", fake_pwsh_script])

    # Execute the fake pwsh script
    _common.log("Launching nc as a child of fake pwsh")
    _common.execute([fake_pwsh_script], timeout=5, kill=True, shell=True)

    # Cleanup
    _common.remove_file(fake_pwsh_script)
