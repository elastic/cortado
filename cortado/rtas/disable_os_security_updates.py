# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="f4e4a28e-c845-4b26-bfdf-24128e73ef21",
    platforms=["macos"],
    endpoint_rules=[
        {"rule_name": "Operating System Security Updates Disabled", "rule_id": "741ad90d-e8d0-4d29-b91b-3d68108cb789"}
    ],
    siem_rules=[{"rule_name": "SoftwareUpdate Preferences Modification", "rule_id": "f683dcdf-a018-4801-b066-193d4ae6c8e5"}],
    techniques=["T1562"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/defaults"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake commands for system discovery with builtin cmds")

    # ER
    _common.execute(
        [
            masquerade,
            "write",
            "-bool",
            "com.apple.SoftwareUpdate",
            "CriticalUpdateInstall",
            "NO",
        ],
        timeout=10,
        kill=True,
    )

    # DR
    _common.execute(
        [masquerade, "write", "-bool", "com.apple.SoftwareUpdate", "NO"],
        timeout=10,
        kill=True,
    )

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
