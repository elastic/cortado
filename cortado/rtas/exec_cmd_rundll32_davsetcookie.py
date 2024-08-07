# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="3a84dc01-0202-4aee-8cd1-5fdefead9f4f",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '4682fd2c-cfae-47ed-a543-9bed37657aa6', 'rule_name': 'Potential Local NTLM Relay via HTTP'}],
    techniques=['T1212'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    rundll32 = "C:\\Users\\Public\\rundll32.exe"
    _common.copy_file(EXE_FILE, rundll32)

    # Execute command
    _common.execute([rundll32, "/c", "echo", "C:\\Windows\\System32\\davclnt.dll,DavSetCookie", "https*/print/pipe/"],
                   timeout=10)
    _common.remove_file(rundll32)


