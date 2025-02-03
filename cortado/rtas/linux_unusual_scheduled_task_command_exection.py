# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0c55d2bd-924b-44a0-8f75-8fb6fc2427bf",
    name="linux_unusual_scheduled_task_command_exection",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="46b142a6-3d54-45e7-ad8a-7a4bc9bfe01c", name="Scheduled Task Unusual Command Execution"),
    ],
    techniques=["T1053", "T1543", "T1059", "T1071"],
)
def main() -> None:
    # Path for the fake systemd script
    fake_systemd = "/tmp/systemd"

    # Create fake sh executable
    masquerade = "/tmp/sh"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake cron script that launches sh
    with Path(fake_systemd).open("w", encoding="utf-8") as script:
        _ = script.write("#!/bin/bash\n")
        _ = script.write('/tmp/sh -c "echo /dev/tcp/8.8.8.8/53"\n')

    # Make the script executable
    _ = _common.execute_command(["chmod", "+x", fake_systemd])

    # Execute the fake cron script
    log.info("Launching a shell that executes a payload as a child of fake systemd")
    _ = _common.execute_command([fake_systemd], timeout_secs=5, shell=True)  # noqa: S604

    # Cleanup
    _common.remove_file(fake_systemd)
