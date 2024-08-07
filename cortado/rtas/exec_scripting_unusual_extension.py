# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="04fa2fff-bbcb-4b13-ad10-33225056e34e",
    name="exec_scripting_unusual_extension",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="b76c0a04-b504-4a2f-a0cf-b4175a2f3eea", name="Execution of a Windows Script with Unusual File Extension"
        )
    ],
    siem_rules=[],
    techniques=["T1059"],
)
def main():
    _common.log("Executing cscript against .exe")
    _common.execute(["cmd.exe", "/c", "cscript.exe", "/e:Vbscript", "cmd.exe"], timeout=5, kill=True)
