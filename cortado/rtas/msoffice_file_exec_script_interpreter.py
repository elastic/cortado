# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="3206f2b2-c731-479f-a258-d486dac8a055",
    name="msoffice_file_exec_script_interpreter",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="54aabea0-3687-4ef1-b70c-015ca588e563", name="Microsoft Office File Execution via Script Interpreter"
        )
    ],
    siem_rules=[],
    techniques=["T1566"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed.exe")

    binary = "winword.exe"
    _common.copy_file(EXE_FILE, binary)

    # Execute command
    _common.log("Dropping executable using fake winword")
    _common.execute([binary, "/c", "copy C:\\Windows\\System32\\cmd.exe cmd.exe"])

    _common.log("Executing it using scripting program")
    _common.execute(
        [
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "-C",
            ".\\cmd.exe /c exit",
        ]
    )

    _common.remove_files(binary, "cmd.exe")
