# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="81adc847-2965-4a4b-8d3c-91e541c85ab4",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '9ccf3ce0-0057-440a-91f5-870c6ad39093',
        'rule_name': 'Command Shell Activity Started via RunDLL32'
    }],
    techniques=['T1059', 'T1059.001'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    rundll32 = "C:\\Users\\Public\\rundll32.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    _common.copy_file(EXE_FILE, rundll32)

    # Execute command
    _common.execute([rundll32, "/c", cmd], timeout=2, kill=True)
    _common.remove_file(rundll32)


if __name__ == "__main__":
    exit(main())
