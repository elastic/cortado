# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import sys

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1b7fe2e7-29c0-4d10-9ced-8b9cd158835d",
    name="binary_execution_from_shared_memory",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="78ae5dbd-477b-4ce7-a7f7-8c4b5e228df2", name="Binary Executed from Shared Memory Directory"),
    ],
    siem_rules=[
        RuleMetadata(id="3f3f9fe2-d095-11ec-95dc-f661ea17fbce", name="Binary Executed from Shared Memory Directory"),
    ],
    techniques=["T1620"],
)
def main() -> None:
    masquerade = "/dev/shm/test"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Executing Fake binary from Shared Memory")
    _ = _common.execute_command([masquerade, "test"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
