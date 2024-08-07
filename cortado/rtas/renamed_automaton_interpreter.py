# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="8c128a2b-fa7b-4bfc-9ec9-934395460420",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="92d720dd-93b2-49e0-b68a-d5d6acbe4910", name="Renamed Windows Automaton Script Interpreter")
    ],
    siem_rules=[],
    techniques=["T1036"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")
RENAMER = _common.get_path("bin", "rcedit-x64.exe")



def main():
    autohotkey = "C:\\Users\\Public\\notaut0hotkey.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    _common.copy_file(EXE_FILE, autohotkey)
    _common.copy_file(RENAMER, rcedit)

    # Execute command
    _common.log("Modifying the OriginalFileName attribute")
    _common.execute(
        [
            rcedit,
            autohotkey,
            "--set-version-string",
            "OriginalFilename",
            "AutoHotkey.exe",
        ]
    )

    _common.execute([autohotkey], timeout=10, kill=True)

    _common.remove_files(autohotkey, rcedit)


if __name__ == "__main__":
    exit(main())
