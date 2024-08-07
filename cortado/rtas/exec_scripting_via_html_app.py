# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="05f1f2a3-430d-4d20-9c0c-767d3b950cbb",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f0630213-c4c4-4898-9514-746395eb9962", name="Script Execution via Microsoft HTML Application")
    ],
    siem_rules=[],
    techniques=["T1218"],
)
def main():
    # Execute Command
    # Had a hard time trying to escape the quotes that would be needed to execute a real command using
    # RunHTMLApplication, this will just fire the rule and result in a Missing entry error
    _common.log("Running rundll32 RunHTMLApplication")
    _common.execute(
        [
            "cmd.exe",
            "/c",
            "rundll32.exe javascript:\\..\\mshtml.dll,RunHTMLApplication",
        ],
        timeout=5,
        kill=True,
    )
