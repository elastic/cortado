# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="0612b920-62d8-4e1c-81c6-e6583571fc49",
    name="linux_execution_kill_from_executable_in_unusual_location",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="b9935dcc-e885-4954-9999-3c016b990737", name="Kill Command Executed from Binary in Unusual Location"
        ),
    ],
    techniques=["T1059", "T1562"],
)
def main() -> None:
    # Path for the fake kill script
    kill_script = "/dev/shm/rta"

    # Create fake executable
    masquerade = "/tmp/kill"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Create a fake script that executes the fake binary
    with Path(kill_script).open("w", encoding="utf-8") as script:
        _ = script.write("#!/bin/bash\n")
        _ = script.write("/tmp/kill\n")

    # Make the script executable
    _ = _common.execute_command(["chmod", "+x", kill_script])

    # Execute the fake script
    log.info("Launching fake kill script")
    _ = _common.execute_command([kill_script], timeout_secs=5, shell=True)

    # Cleanup
    _common.remove_file(kill_script)
    _common.remove_file(masquerade)
