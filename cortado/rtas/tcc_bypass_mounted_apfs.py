# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4c8675a8-fbed-4f36-88e6-ffceaf82f426",
    name="tcc_bypass_mounted_apfs",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="b00bcd89-000c-4425-b94c-716ef67762f6", name="TCC Bypass via Mounted APFS Snapshot Access")
    ],
    techniques=["T1006"],
)
def main():
    masquerade = "/tmp/mount_apfs"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake mount_apfs command to mount the APFS snapshot")
    _ = _common.execute_command([masquerade, "/System/Volumes/Data", "noowners"], timeout_secs=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
