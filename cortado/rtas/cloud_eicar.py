# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import sys

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8d6f2979-747a-42d9-813a-ddadd90650d2",
    name="cloud_eicar",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="7b9ddfc8-8ea8-45d5-b62f-3fbd142c8f08", name="Behavior Protection - Cloud Reputation EICAR"),
    ],
    techniques=["TA0002"],
)
def main() -> None:
    masquerade = "/tmp/bash"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching Behavior Protection - Cloud Reputation EICAR")
    _ = _common.execute_command([masquerade, "test-cloudreputationrule-5020a0031cad"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
