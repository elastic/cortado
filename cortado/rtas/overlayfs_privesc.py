# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, _common

metadata = RtaMetadata(
    id="a78663dc-9561-40a9-b4eb-f15e31c690cc",
    platforms=["linux"],
    endpoint_rules=[
        {
            "rule_name": "Potential Privilege Escalation via OverlayFS",
            "rule_id": "ca9de348-a09d-4c67-af21-5645b70003d0",
        },
    ],
    siem_rules=[
        {
            "rule_name": "Potential Privilege Escalation via OverlayFS",
            "rule_id": "b51dbc92-84e2-4af1-ba47-65183fcd0c57",
        },
    ],
    techniques=["T1068"],
)


@_common.requires_os(*metadata.platforms)
def main() -> None:
    _common.log("Creating a fake unshare executable..")
    masquerade = "/tmp/unshare"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    commands = [masquerade, "-rm", "cap_setuid"]

    _common.log("Launching fake commands to set cap_setuid via unshare")
    _common.execute([*commands], timeout=2, kill=True)
    _common.log("Unshare simulation succesful")

    _common.log("Faking uid change via same parent")

    sudo_commands = ["sudo", "su"]

    _common.execute([*sudo_commands], timeout=2, kill=True)

    _common.log("Uid change simulation succesful")

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
