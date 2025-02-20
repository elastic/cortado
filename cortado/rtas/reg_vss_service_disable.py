# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c4eefb59-2c59-4904-a04e-5e3a75f54a46",
    name="reg_vss_service_disable",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="b2409cd4-3b23-4b2d-82e4-bbb25594999a", name="Shadow Copy Service Disabled via Registry Modification"
        ),
        RuleMetadata(
            id="d6cde651-adc9-4074-b167-65e6b82116b4", name="VSS Service Disabled Followed by a Suspicious File Rename"
        ),
        RuleMetadata(id="df874d7e-6639-44ce-b47d-96254022ccd5", name="Suspicious File Rename by an Unusual Process"),
    ],
    techniques=["T1218", "T1112", "T1486", "T1490", "T1059"],
)
def main():
    HIGHENTROPY = _common.get_resource_path("bin/highentropy.txt")

    key = "SYSTEM\\CurrentControlSet\\Services\\VSS"
    value = "Start"
    data = 4

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data, data_type="dword"):
        pass

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    jpg = "C:\\Users\\Public\\jpg.jpg"
    jpgenc = "C:\\Users\\Public\\jpg.enc"
    # Creating a high entropy file, and executing the rename operation
    _common.copy_file(HIGHENTROPY, jpg)
    _ = _common.execute_command([powershell, "/c", f"Rename-Item {jpg} {jpgenc}"], timeout_secs=10)
    _ = _common.execute_command([powershell, "/c", "Remove-Item 'C:\\Users\\Public\\*jpg*' -Force"], timeout_secs=10)
