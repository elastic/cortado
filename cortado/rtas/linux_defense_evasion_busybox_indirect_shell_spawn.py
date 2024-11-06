# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="6d30e1d0-6f03-4075-9267-fb179e8b9f11",
    name="linux_defense_evasion_busybox_indirect_shell_spawn",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="895ed985-a6ae-4ebe-b688-7ca8cd6e2e23", name="Proxy Shell Execution via Busybox"),
    ],
    techniques=["T1218", "T1059"],
)
def main() -> None:
    # Path for the fake script
    rta_script = "/tmp/busybox"

    # Create fake executable
    masquerade = "/tmp/bash"
    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    _common.execute_command(["chmod", "+x", masquerade])

    # Create a fake script that executes a fake binary
    with Path(rta_script).open("w", encoding="utf-8") as script:
        script.write("#!/bin/bash\n")
        script.write("/tmp/bash\n")

    # Make the script executable
    _common.execute_command(["chmod", "+x", rta_script])

    # Execute the fake script
    log.info("Launching fake script")
    _common.execute_command([rta_script], timeout=5, kill=True, shell=True)  # noqa: S604

    # Cleanup
    _common.remove_file(rta_script)
    _common.remove_file(masquerade)
