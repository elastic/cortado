# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4e63cb99-b56d-4c75-9cda-3a7f30861d35",
    name="user_action_script",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="c292fa52-4115-408a-b897-e14f684b3cb7", name="Persistence via Folder Action Script")],
    techniques=["T1037", "T1059"],
)
def main():
    # create masquerades
    masquerade = "/tmp/com.apple.foundation.UserScriptService"
    masquerade2 = "/tmp/osascript"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)

    # Execute command
    log.info("Launching fake commands to mimic modification of a Folder Action script")
    _ = _common.execute_command([masquerade, "childprocess", masquerade2], timeout_secs=1)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
