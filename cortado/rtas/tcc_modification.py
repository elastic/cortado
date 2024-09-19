# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="34cddcb3-bd49-4363-8092-677307abaa82",
    name="tcc_modification",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="eea82229-b002-470e-a9e1-00be38b14d32", name="Potential Privacy Control Bypass via TCCDB Modification"
        )
    ],
    techniques=["T1562"],
)
def main():
    masquerade = "/tmp/sqlite"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake plistbuddy command to modify plist files")
    _ = _common.execute_command(
        [masquerade, "/test/Application Support/com.apple.TCC/TCC.db"],
        timeout_secs=10,
    )

    # cleanup
    _common.remove_file(masquerade)
