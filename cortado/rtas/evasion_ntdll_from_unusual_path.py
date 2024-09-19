# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.


import time
import os
import logging
from pathlib import Path

from . import OSType, register_code_rta, RuleMetadata

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

    import win32api  # type: ignore
    import win32file  # type: ignore

    ntdll_path = os.path.expandvars("%systemroot%\\system32\\ntdll.dll")
    notntdll_path = os.path.expandvars("%localappdata%\\Temp\\notntdll.dll")

    win32file.CopyFile(ntdll_path, notntdll_path, 0) # type: ignore

    if Path(notntdll_path).is_file():
        log.info("NTDLL copied")
        r = win32api.LoadLibrary(notntdll_path) # type: ignore
        if r > 0:
            log.info("NTDLL copy loaded")
            time.sleep(1)
            win32api.FreeLibrary(r)  # type: ignore
            win32file.DeleteFile(notntdll_path)
            log.info("NTDLL copy deleted")
        else:
            log.info("Failed to load ntdll")
