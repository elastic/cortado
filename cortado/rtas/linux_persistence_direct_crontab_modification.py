# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import RuleMetadata, _common, register_code_rta, OSType

log = logging.getLogger(__name__)


@register_code_rta(
    id="a1286125-bf4b-40bb-819a-b7c5de83fafb",
    name="linux_persistence_direct_crontab_modification",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="b3bcbab6-e216-4d70-bdee-2b69affbb386", name="Potential Persistence via Direct Crontab Modification"
        ),
    ],
    techniques=["T1053"],
)
def main() -> None:
    # Path for the fake script
    rta_script = "/dev/shm/rta"

    # Create fake executable
    masquerade = "/tmp/crontab"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    _ = _common.execute_command(["chmod", "+x", masquerade])

    # Create a fake script that executes the fake binary
    with Path(rta_script).open("w", encoding="utf-8") as script:
        _ = script.write("#!/bin/bash\n")
        _ = script.write("/tmp/crontab -\n")

    # Make the script executable
    _ = _common.execute_command(["chmod", "+x", rta_script])

    # Execute the fake script
    log.info("Launching fake script")
    _ = _common.execute_command([rta_script], timeout_secs=5, shell=True)

    # Cleanup
    _common.remove_file(rta_script)
    _common.remove_file(masquerade)
