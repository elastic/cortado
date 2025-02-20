# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0427904d-1fba-40f4-a423-ea555d1a2335",
    name="exec_cmd_net_stop",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="035889c4-2686-4583-a7df-67f89c292f2c", name="High Number of Process and/or Service Terminations"
        )
    ],
    techniques=["T1489"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    net = "C:\\Users\\Public\\net.exe"
    _common.copy_file(EXE_FILE, net)

    # Execute command
    for _ in range(0, 10):
        _ = _common.execute_command([net, "/c", "echo", "stop"], timeout_secs=10)
    _common.remove_file(net)
