# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="459d7b3c-2c6d-4101-b830-d6c317d4b355",
    name="opera_child_process",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="080bc66a-5d56-4d1f-8071-817671716db9", name="Suspicious Browser Child Process")],
    techniques=["T1203", "T1189"],
)
def main():
    # create masquerades
    masquerade = "/tmp/Opera"
    masquerade2 = "/tmp/curl"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)

    # Execute command
    log.info("Launching fake macOS installer commands to download payload")

    command = f"{masquerade2} test.amazonaws.comtest"
    _ = _common.execute_command([masquerade, "childprocess", command], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
