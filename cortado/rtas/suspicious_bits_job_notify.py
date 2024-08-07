# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="bc4c85e7-c2c6-497c-a52e-7c8896a79ab2",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': 'c3b915e0-22f3-4bf7-991d-b643513c722f', 'rule_name': 'Persistence via BITS Job Notify Cmdline'}],
    techniques=['T1197'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    svchost = "C:\\Users\\Public\\svchost.exe"
    child = "C:\\Users\\Public\\child.exe"
    _common.copy_file(EXE_FILE, child)
    _common.copy_file(EXE_FILE, svchost)

    _common.execute([svchost, "echo", "BITS", ";", child], timeout=5, kill=True)
    _common.remove_files(child, svchost)


