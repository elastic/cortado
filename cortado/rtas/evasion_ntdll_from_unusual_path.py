# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.


import logging
from pathlib import Path

from . import OSType, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="e6d5315f-4c70-4788-8564-e7c23786a4d0",
    name="evasion_ntdll_from_unusual_path",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="3205274e-7eb0-4765-a712-5783361091ae", name="NTDLL Loaded from an Unusual Path")],
    siem_rules=[],
    techniques=["T1055"],
)
def main():
    import time
    from os import path

    import win32api
    import win32file

    win32file.CopyFile(
        path.expandvars("%systemroot%\\system32\\ntdll.dll"), path.expandvars("%localappdata%\\Temp\\notntdll.dll"), 0
    )
    if Path(path.expandvars("%localappdata%\\Temp\\notntdll.dll")).is_file():
        print("[+] - NTDLL copied")
        r = win32api.LoadLibrary(path.expandvars("%localappdata%\\Temp\\notntdll.dll"))
        if r > 0:
            print("[+] - NTDLL copy loaded")
            time.sleep(1)
            win32api.FreeLibrary(r)
            win32file.DeleteFile(path.expandvars("%localappdata%\\Temp\\notntdll.dll"))
            print("[+] - NTDLL copy deleted")
        else:
            print("f[+] - Failed to load ntdll")
