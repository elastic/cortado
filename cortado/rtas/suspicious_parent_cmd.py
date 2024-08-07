# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="41ea3472-7ec7-4c4a-baf4-b1805ba597df",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '3b47900d-e793-49e8-968f-c90dc3526aa1', 'rule_name': 'Unusual Parent Process for cmd.exe'}],
    techniques=['T1059'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    logonui = "C:\\Users\\Public\\logonui.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    _common.copy_file(EXE_FILE, logonui)

    # Execute command
    _common.execute([logonui, "/c", cmd], timeout=2, kill=True)
    _common.remove_file(logonui)


