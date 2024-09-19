# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b2603bac-ba1c-4e6e-a041-ed8772fded75",
    name="multiarch_file_drops",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="276a5df0-7e20-4218-ade1-3f3ed711d4cb", name="Potential Multi Architecture File Downloads")
    ],
    siem_rules=[],
    techniques=["T1105"],
)
def main():
    masquerade = "/tmp/curl"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching fake commands to mimic multi arch file downloads")
    command = "http://fake/mipsel"

    for _ in range(8):
        _ = _common.execute_command([masquerade, command], timeout_secs=0.3)

    # cleanup
    _common.remove_file(masquerade)
