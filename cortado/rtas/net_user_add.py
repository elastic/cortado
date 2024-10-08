# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Create User with net.exe
# RTA: net_user_add.py
# ATT&CK: T1136
# signal.rule.name: User Account Creation
# Description: Adds an account to the local host using the net.exe command

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="7884fa56-c4d6-494f-bfa5-825851ee0fda",
    name="net_user_add",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="41b638a1-8ab6-4f8e-86d9-466317ef2db5", name="Potential Hidden Local User Account Creation")
    ],
    techniques=["T1078"],
)
def main():
    log.info("Creating local and domain user accounts using net.exe")
    commands = [
        'net.exe user macgyver $w!$$@rmy11 /add /fullname:"Angus Macgyver"',
        'net.exe user macgyver $w!$$@rmy11 /add /fullname:"Angus Macgyver" /domain',
        "net.exe group  Administrators macgyver /add",
        'net.exe group  "Domain Admins"  macgyver  /add  /domain',
        "net.exe localgroup Administrators macgyver /add",
    ]

    for cmd in commands:
        _ = _common.execute_command([cmd])

    cleanup_commands = [
        "net.exe user macgyver /delete",
        "net.exe user macgyver /delete /domain",
    ]

    log.info("Removing local and domain user accounts using net.exe")
    for cmd in cleanup_commands:
        _ = _common.execute_command([cmd])
