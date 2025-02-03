# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c2b89791-5c51-4965-a440-cd9905bfbe55",
    name="linux_cron_hidden_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="e8b2afe5-37a9-468c-a6fb-f178d46cb698", name="Hidden Payload Executed via Cron"),
    ],
    techniques=["T1053"],
)
def main() -> None:
    # Path for the fake cron script
    fake_cron = "/tmp/cron"

    # Create fake sh executable
    masquerade = "/tmp/sh"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake cron script that launches sh
    with Path(fake_cron).open("w", encoding="utf-8") as script:
        _ = script.write("#!/bin/bash\n")
        _ = script.write("/tmp/sh -c '/dev/shm/.foo'\n")

    # Make the script executable
    _ = _common.execute_command(["chmod", "+x", fake_cron])

    # Execute the fake cron script
    log.info("Launching a shell that executes a hidden payload as a child of fake cron")
    _ = _common.execute_command([fake_cron], timeout_secs=5, shell=True)

    # Cleanup
    _common.remove_file(fake_cron)
