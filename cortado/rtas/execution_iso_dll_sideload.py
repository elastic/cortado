# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path


# iso contains WerFault.exe and a testing faultrep.dll to be sideloaded
ISO = _common.get_path("bin", "werfault_iso.iso")
PROC = "WER_RTA.exe"


@register_code_rta(
    id="ba802fb2-f183-420e-947b-da5ce0c74d123",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="ba802fb2-f183-420e-947b-da5ce0c74dd3", name="Potential DLL SideLoad via a Microsoft Signed Binary"
        )
    ],
    techniques=["T1574", "T1574.002"],
)
def main():
    # ps script to mount, execute a file and unmount ISO device
    PS_SCRIPT = _common.get_path("bin", "ExecFromISOFile.ps1")

    if Path(ISO).is_file() and Path(PS_SCRIPT).is_file():
        print(f"[+] - ISO File {ISO} will be mounted and executed via powershell")

        # import ExecFromISO function that takes two args -ISOFIle pointing to ISO file path and -procname pointing to the filename to execute
        command = f"powershell.exe -ExecutionPol Bypass -c import-module {PS_SCRIPT}; ExecFromISO -ISOFile {ISO} -procname {PROC};"
        _common.execute(command)
        print(f"[+] - RTA Done!")
