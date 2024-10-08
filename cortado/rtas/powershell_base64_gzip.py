# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: PowerShell with base64/gzip
# RTA: powershell_base64_gzip.py
# ATT&CK: T1140
# Description: Calls PowerShell with command-line that contains base64/gzip

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="38defc7e-7234-45a2-83ef-e845d0eba3f2",
    name="powershell_base64_gzip",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="81fe9dc6-a2d7-4192-a2d8-eed98afc766a", name="PowerShell Suspicious Payload Encoded and Compressed"
        )
    ],
    techniques=["T1140", "T1027", "T1059"],
)
def main():
    log.info("PowerShell with base64/gzip")

    command = "powershell.exe -noni -nop -w hidden -c &([scriptblock]::create((New-Object IO.StreamReader(New-Object IO.Compression.GzipStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String(aaa)"  # noqa: E501
    _ = _common.execute_command(command, shell=True)
