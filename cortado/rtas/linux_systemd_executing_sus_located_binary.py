# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5b277316-4584-4e4f-8a71-6c7d833e2c30",
    name="linux_systemd_executing_sus_located_binary",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="f2a52d42-2410-468b-9910-26823c6ef822", name="Scheduled Job Executing Binary in Unusual Location"
        )
    ],
    techniques=["T1543", "T1053"],
)
def main():
    # Path for the fake systemd script
    fake_systemd = "/tmp/systemd"

    # Create fake sh executable
    masquerade = "/tmp/sh"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake systemd script that launches sh
    with open(fake_systemd, "w") as script:
        _ = script.write("#!/bin/bash\n")
        _ = script.write("/tmp/sh\n")

    # Make the script executable
    _ = _common.execute_command(["chmod", "+x", fake_systemd])
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Execute the fake systemd script
    log.info("Launching a shell that executes a payload as a child of fake systemd")
    _ = _common.execute_command([fake_systemd], timeout_secs=5, shell=True)

    # Cleanup
    _common.remove_file(fake_systemd)
