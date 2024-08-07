# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="0da48a27-4a5e-4974-ba6a-63cce8f602df",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': 'b25a7df2-120a-4db2-bd3f-3e4b86b24bee', 'rule_name': 'Remote File Copy via TeamViewer'}],
    techniques=['T1105', 'T1219'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    teamviewer = "C:\\Users\\Public\\teamviewer.exe"
    fake_exe = "C:\\Users\\Public\\a.exe"
    _common.copy_file(EXE_FILE, teamviewer)

    # Execute command
    _common.execute([teamviewer, "/c", f"echo AAAAAAAAAA | Out-File {fake_exe}"], timeout=10)
    _common.remove_files(fake_exe, teamviewer)


if __name__ == "__main__":
    exit(main())
