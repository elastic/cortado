# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="58041706-c636-4043-b221-3d59f977b7e2",
    name="edmond_child_process",
    platforms=[OSType.MACOS],
    endpoint_rules=[RuleMetadata(id="1cd247d8-00e8-4c62-b9ee-90cd1811460b", name="Potential Persistence via Emond")],
    siem_rules=[RuleMetadata(id="3e3d15c6-1509-479a-b125-21718372157e", name="Suspicious Emond Child Process")],
    techniques=["T1546"],
)
def main():
    masquerade = "/tmp/emond"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching bash from fake emond command")
    _ = _common.execute_command(masquerade, shell=True, timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
