# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path



@register_code_rta(
    id="a4355bfc-aa15-43f6-a36d-523aa637127b",
    platforms=[OSType.WINDOWS],
    siem_rules=[],
    endpoint_rules=[RuleMetadata(id="0cdf1d24-b1c3-4952-a400-5ba3c1491087", name="Persistence via a Process from a Removable or Mounted ISO Device"), 
              RuleMetadata(id="3c12c648-e29f-4bff-9157-b07f2cbddf1a", name="Scheduled Task from a Removable or Mounted ISO Device")],
    techniques=["T1071", "T1204"],
)

# iso contains cmd.exe to test for rules looking for persistence from a PE from a mounted ISO or its descendants
ISO = _common.get_path("bin", "cmd_from_iso.iso")
PROC = 'cmd.exe'

# ps script to mount, execute a file and unmount ISO device
PS_SCRIPT = _common.get_path("bin", "ExecFromISOFile.ps1")



def main():
    if Path(ISO).is_file() and Path(PS_SCRIPT).is_file():
        print(f'[+] - ISO File {ISO} will be mounted and executed via powershell')

        # commands to trigger two unique rules looking for persistence from a mounted ISO file
        for arg in ["'/c reg.exe add hkcu\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v FromISO /d test.exe /f'", "'/c SCHTASKS.exe /Create /TN FromISO /TR test.exe /sc hourly /F'"] :

            # import ExecFromISO function that takes two args -ISOFIle pointing to ISO file path and -procname pointing to the filename to execute and -cmdline for arguments
            command = f"powershell.exe -ExecutionPol Bypass -c import-module {PS_SCRIPT}; ExecFromISO -ISOFile {ISO} -procname {PROC} -cmdline {arg};"
            _common.execute(command)
        # cleanup
        rem_cmd = "reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v FromISO"
        _common.execute(["cmd.exe", "/c", rem_cmd], timeout=10)
        _common.execute(["SCHTASKS.exe", "/delete", "/TN", "FromISO", "/F"])
        print(f'[+] - RTA Done!')

if __name__ == "__main__":
    exit(main())
