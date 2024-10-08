# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import sys

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a78663dc-9561-40a9-b4eb-f15e31c690cc",
    name="overlayfs_privesc",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="ca9de348-a09d-4c67-af21-5645b70003d0", name="Potential Privilege Escalation via OverlayFS"),
    ],
    siem_rules=[
        RuleMetadata(id="b51dbc92-84e2-4af1-ba47-65183fcd0c57", name="Potential Privilege Escalation via OverlayFS"),
    ],
    techniques=["T1068"],
)
def main() -> None:
    log.info("Creating a fake unshare executable..")
    masquerade = "/tmp/unshare"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    commands = [masquerade, "-rm", "cap_setuid"]

    log.info("Launching fake commands to set cap_setuid via unshare")
    _ = _common.execute_command(commands, timeout_secs=2)
    log.info("Unshare simulation succesful")

    log.info("Faking uid change via same parent")

    sudo_commands = ["sudo", "su"]

    _ = _common.execute_command(
        [*sudo_commands],
        timeout_secs=2,
    )

    log.info("Uid change simulation succesful")

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
