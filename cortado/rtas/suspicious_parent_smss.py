# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="46463426-0a03-448a-afe3-9215841ec86d",
    name="suspicious_parent_smss",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="05b358de-aa6d-4f6c-89e6-78f74018b43b", name="Conhost Spawned By Suspicious Parent Process")
    ],
    techniques=["T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    smss = "C:\\Users\\Public\\smss.exe"
    conhost = "C:\\Users\\Public\\conhost.exe"
    _common.copy_file(EXE_FILE, smss)
    _common.copy_file(EXE_FILE, conhost)

    # Execute command
    _ = _common.execute_command([smss, "/c", conhost], timeout_secs=2, kill=True)
    _common.remove_files([smss, conhost])
