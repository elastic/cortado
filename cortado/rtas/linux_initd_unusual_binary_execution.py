# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4076de6c-6caa-40b3-bfb6-548645823376",
    name="linux_initd_unusual_binary_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="879c083c-e2d9-4f75-84f2-0f1471d915a8", name="Init.d Script Executed Binary from Unusual Location"
        )
    ],
    techniques=["T1037"],
)
def main():
    # Path for the fake initd script
    fake_initd = "/etc/init.d/rta"

    # Create fake sh executable
    masquerade = "/tmp/sh"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake initd script that launches sh
    with open(fake_initd, "w") as script:
        script.write("#!/bin/bash\n")
        script.write("/tmp/sh\n")

    # Make the script executable
    _ = _common.execute_command(["chmod", "+x", fake_initd])
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Execute the fake initd script
    log.info("Launching a shell that executes a payload as a child of fake initd")
    _ = _common.execute_command([fake_initd], timeout_secs=5, kill=True, shell=True)

    # Cleanup
    _common.remove_file(fake_initd)
