# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="65c661e6-7a15-45c0-97ad-0635eda560ba",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_name": "Suspicious Execution via Microsoft Office Add-Ins",
            "rule_id": "9efd977a-6d4a-4cc8-8ab3-355587b0ef69",
        }
    ],
    siem_rules=[],
    techniques=["T1137", "T1566"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    winword = "C:\\Users\\Public\\winword.exe"
    _common.copy_file(EXE_FILE, winword)

    # Execute command
    _common.execute([powershell, "/c", winword, "/c", "echo", "doc.wll"], timeout=5, kill=True)
    _common.remove_file(winword)


if __name__ == "__main__":
    exit(main())
