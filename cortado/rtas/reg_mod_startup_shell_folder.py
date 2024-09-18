# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="16fe008f-58b5-4a8c-9e73-2784edf636b1",
    name="reg_mod_startup_shell_folder",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="c8b150f0-0164-475b-a75e-74b47800a9ff", name="Suspicious Startup Shell Folder Modification")
    ],
    techniques=["T1547", "T1547.001"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
    value = "Common Startup"
    uvalue = "Startup"
    data = "Test"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
    with _common.temporary_reg(_common.HKCU, key, uvalue, data):
        pass
