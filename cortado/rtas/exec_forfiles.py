# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="8c22e0f5-7c5b-46eb-b04c-28f32ac5b564",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[{
        'rule_id': '78afa378-d1c4-4b83-a261-ce1c90f1cbf9',
        'rule_name': 'Indirect Command Execution via ForFiles'
    }],
    siem_rules=[],
    techniques=[""],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    forfiles = "C:\\Users\\Public\\forfiles.exe"
    _common.copy_file(EXE_FILE, forfiles)

    # Execute command
    _common.execute([forfiles, "/c", "/m", "/p"], timeout=10, kill=True)

    _common.remove_file(forfiles)


if __name__ == "__main__":
    exit(main())
