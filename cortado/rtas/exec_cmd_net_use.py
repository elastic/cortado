# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="46f6ae71-2fd8-46bd-8209-9fc0f59432ef",
    name="exec_cmd_net_use",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="c4210e1c-64f2-4f48-b67e-b5a8ffe3aa14", name="Mounting Hidden or WebDav Remote Shares")
    ],
    techniques=["T1021", "T1021.002", "T1078", "T1078.003"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    net = "C:\\Users\\Public\\net.exe"
    _common.copy_file(EXE_FILE, net)

    # Execute command
    _ = _common.execute_command([net, "/c", "echo", "use", "http"], timeout_secs=10)
    _common.remove_file(net)
