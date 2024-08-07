# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="537de67d-8ba8-4df8-a965-75ca564d0846",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="be42f9fc-bdca-41cd-b125-f223d09eef69",
            name="Script Interpreter Process Writing to Commonly Abused Persistence Locations",
        ),
        RuleMetadata(
            id="a85000c8-3eac-413b-8353-079343c2b6f0", name="Startup Persistence via Windows Script Interpreter"
        ),
    ],
    siem_rules=[],
    techniques=["T1547", "T1059"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    _common.log("Dropping executable to Startup Folder using powershell")
    _common.execute(
        [
            powershell,
            "-C",
            "Copy-Item",
            "C:\\Windows\\System32\\cmd.exe",
            "'C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\'",
        ]
    )

    _common.log("Dropping executable to Startup Folder using powershell")
    _common.execute(
        [
            powershell,
            "-C",
            "Copy-Item",
            "C:\\Windows\\System32\\cmd.exe",
            "'C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\cmd2.exe'",
        ]
    )

    _common.remove_files(
        "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\cmd2.exe",
        "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\cmd.exe",
    )
