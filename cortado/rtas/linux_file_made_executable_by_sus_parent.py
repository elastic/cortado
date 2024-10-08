# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="97993aa0-7b15-442b-a180-7c158b3339c1",
    name="linux_file_made_executable_by_sus_parent",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="742037b3-3ef6-4a33-84ed-b26fc6ae322c", name="Linux File Made Executable by Suspicious Parent")
    ],
    techniques=["T1222", "T1564"],
)
def main():
    masquerade = "/tmp/chmod"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "+x", "/dev/shm/foo"]

    # Execute command
    log.info("Launching fake command to simulate chmod")
    _ = _common.execute_command(commands, timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
