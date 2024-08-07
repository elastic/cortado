# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
import sys
from pathlib import Path


@register_code_rta(
    id="11b447ca-6ad4-4597-a048-2585b27762ea",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="94943f02-5580-4d1d-a763-09e958bd0f57", name="Shell Command Execution via kworker")
    ],
    siem_rules=[],
    techniques=["T1036", "T1059"],
)
@_common.requires_os(metadata.platforms)
def main() -> None:
    masquerade_script = Path("/tmp/kworker_evasion.sh")
    with masquerade_script.open("w") as f:
        f.write("#!/bin/bash\n")
        f.write("sh -c 'whoami'\n")

    # Make the script executable
    masquerade_script.chmod(0o755)

    # Execute the script
    _common.log("Launching fake command to simulate a kworker execution")
    os.system(str(masquerade_script))  # noqa: S605

    # Cleanup
    masquerade_script.unlink()


if __name__ == "__main__":
    sys.exit(main())
