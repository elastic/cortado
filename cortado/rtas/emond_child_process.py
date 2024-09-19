# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d1988e82-a079-4fc2-99f7-2bdbc9af0e00",
    name="emond_child_process",
    platforms=[OSType.MACOS],
    endpoint_rules=[RuleMetadata(id="1cd247d8-00e8-4c62-b9ee-90cd1811460b", name="Potential Persistence via Emond")],
    siem_rules=[RuleMetadata(id="3e3d15c6-1509-479a-b125-21718372157e", name="Suspicious Emond Child Process")],
    techniques=["T1546"],
)
def main():
    # create masquerades
    masquerade = "/tmp/emond"
    masquerade2 = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)

    # Execute commands
    log.info("Launching fake emond commands to mimic spawning child process.")
    _ = _common.execute_command([masquerade, "childprocess", masquerade2], timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
