# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d275922f-a702-4668-a77d-c60e8df58646",
    name="mount_smbfs",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="661545b4-1a90-4f45-85ce-2ebd7c6a15d0", name="Attempt to Mount SMB Share via Command Line")
    ],
    techniques=["T1021"],
)
def main():
    masquerade = "/tmp/mount_smbfs"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake mount_smbfs command to mimic mounting a network share.")
    _ = _common.execute_command([masquerade], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
