# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="11b447ca-6ad4-4597-a048-2585b27762ea",
    name="exec_shell_kworker",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="94943f02-5580-4d1d-a763-09e958bd0f57", name="Shell Command Execution via kworker")
    ],
    techniques=["T1036", "T1059"],
)
def main() -> None:
    masquerade_script = Path("/tmp/kworker_evasion.sh")
    with masquerade_script.open("w") as f:
        _ = f.write("#!/bin/bash\n")
        _ = f.write("sh -c 'whoami'\n")

    # Make the script executable
    masquerade_script.chmod(0o755)

    # Execute the script
    log.info("Launching fake command to simulate a kworker execution")

    _ = _common.execute_command([_common.get_cmd_path(), str(masquerade_script)])

    # Cleanup
    masquerade_script.unlink()
