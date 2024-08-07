# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Searching Credential Vaults via VaultCmd
# RTA: vaultcmd_commands.py
# ATT&CK: T1003
# Description: Lists the Windows Credential Vaults on the endpoint

import sys

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="53d071d9-36e3-4b40-83c8-d818bd831010",
    name="vaultcmd_commands",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="be8afaed-4bcd-4e0a-b5f9-5562003dde81", name="Searching for Saved Credentials via VaultCmd")
    ],
    techniques=["T1555", "T1003"],
)
def main():
    _common.log("Searching Credential Vaults via VaultCmd")

    _common.execute(["vaultcmd.exe", "/list"])
