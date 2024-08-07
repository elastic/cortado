# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from pathlib import Path


@register_code_rta(
    id="be8c9227-8266-4d91-931e-c53e07731d07",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {
            "rule_name": "Linux User Discovery Command Execution from Suspicious Directory",
            "rule_id": "c932c9f0-76ed-4d78-a242-cfaade43080c",
        },
    ],
    techniques=["T1059", "T1033"],
)
def main() -> None:
    # Path for the fake executable
    fake_executable = "/dev/shm/evil"

    # Create fake whoami executable
    masquerade = "/dev/shm/whoami"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake executable that launches whoami
    with Path(fake_executable).open("w") as script:
        script.write("#!/bin/bash\n")
        script.write("/dev/shm/whoami\n")

    # Make the script executable
    _common.execute(["chmod", "+x", fake_executable])

    # Execute the fake executable
    _common.log("Launching whoami as a child of fake executable")
    _common.execute([fake_executable], timeout=5, kill=True, shell=True)  # noqa: S604

    # Cleanup
    _common.remove_file(fake_executable)
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
