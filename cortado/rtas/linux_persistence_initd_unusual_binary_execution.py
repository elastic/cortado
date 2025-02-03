# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="0560d795-bdd6-4a91-97ad-8e2c2d8143ef",
    name="linux_persistence_initd_unusual_binary_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="879c083c-e2d9-4f75-84f2-0f1471d915a8",
            name="System V Init (init.d) Executed Binary from Unusual Location",
        ),
    ],
    techniques=["T1037"],
)
def main() -> None:
    # Path for the fake initd script
    initd_script = "/etc/init.d/rta"

    # Create fake executable
    masquerade = "/dev/shm/evil"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake script that executes the fake binary
    with Path(masquerade).open("w", encoding="utf-8") as script:
        _ = script.write("#!/bin/bash\n")
        _ = script.write("/dev/shm/evil\n")

    # Make the script executable
    _ = _common.execute_command(["chmod", "+x", initd_script])

    # Execute the fake script
    log.info("Launching fake initd script")
    _ = _common.execute_command([initd_script], timeout_secs=5, shell=True)

    # Cleanup
    _common.remove_file(initd_script)
    _common.remove_file(masquerade)
