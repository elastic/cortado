# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import sys
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="be8c9227-8266-4d91-931e-c53e07731d07",
    name="linux_discovery_command_from_sus_dir",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="c932c9f0-76ed-4d78-a242-cfaade43080c",
            name="Linux User Discovery Command Execution from Suspicious Directory",
        ),
    ],
    techniques=["T1059", "T1033"],
)
def main() -> None:
    # Path for the fake executable
    fake_executable = "/dev/shm/evil"

    # Create fake whoami executable
    masquerade = "/dev/shm/whoami"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake executable that launches whoami
    with Path(fake_executable).open("w") as script:
        script.write("#!/bin/bash\n")
        script.write("/dev/shm/whoami\n")

    # Make the script executable
    _ = _common.execute_command(["chmod", "+x", fake_executable])

    # Execute the fake executable
    log.info("Launching whoami as a child of fake executable")
    _ = _common.execute_command([fake_executable], timeout_secs=5, shell=True)  # noqa: S604

    # Cleanup
    _common.remove_file(fake_executable)
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
