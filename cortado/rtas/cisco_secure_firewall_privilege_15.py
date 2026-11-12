# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Cisco Secure Firewall User Promoted to Privilege Level 15
# RTA: cisco_secure_firewall_privilege_15.py
# Description: Sends a synthetic Cisco Secure Firewall 502103 event that
#              promotes rta-admin from privilege level 5 to level 15.
#
#              The same raw message is accepted by the pinned Cisco ASA and
#              Cisco FTD parsers. Point the RTA at the listener for the dataset
#              being tested; the sender cannot select the data stream.

from . import OSType, RuleMetadata, register_code_rta
from ._cisco_syslog import build_asa_message, send_syslog

APPLIANCE_NAME = "ftd-rta"
ADMIN_USER = "rta-admin"
OLD_PRIVILEGE = 5
NEW_PRIVILEGE = 15


@register_code_rta(
    id="a691debf-719f-43e6-9c6d-ef2dfb535367",
    name="cisco_secure_firewall_privilege_15",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="703e11a7-8374-4ac6-948f-28395479245d",
            name="Cisco Secure Firewall User Promoted to Privilege Level 15",
        )
    ],
    techniques=["T1098"],
)
def main() -> None:
    """Send one Secure Firewall privilege-promotion event."""
    body = (
        f"User priv level changed: Uname: {ADMIN_USER} "
        f"From: {OLD_PRIVILEGE} To: {NEW_PRIVILEGE}"
    )
    send_syslog([build_asa_message(502103, body, appliance=APPLIANCE_NAME)])
