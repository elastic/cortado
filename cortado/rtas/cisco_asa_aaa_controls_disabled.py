# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Cisco ASA AAA Controls Disabled
# RTA: cisco_asa_aaa_controls_disabled.py
# Description: Sends a synthetic Cisco ASA 111010 administrative-command
#              syslog event that disables command accounting.
#
#              Point this RTA at an Elastic Agent Cisco ASA integration
#              listener. The listener, not the sender, selects the data stream.

from . import OSType, RuleMetadata, register_code_rta
from ._cisco_syslog import build_asa_message, send_syslog

APPLIANCE_NAME = "asa-rta"
ADMIN_USER = "rta-admin"
ADMIN_SOURCE_IP = "192.0.2.10"
COMMAND = "no aaa accounting command privilege 15"


@register_code_rta(
    id="9d8f143d-64a8-41a3-8be9-f91307dad4bb",
    name="cisco_asa_aaa_controls_disabled",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="85ae2037-6e32-42fb-9462-17ced12dfa51",
            name="Cisco ASA AAA Controls Disabled",
        )
    ],
    techniques=["T1562.001"],
)
def main() -> None:
    """Send one ASA 111010 event containing a positive AAA command."""
    body = (
        f"User '{ADMIN_USER}', running 'CLI' from IP {ADMIN_SOURCE_IP}, "
        f"executed '{COMMAND}'"
    )
    send_syslog([build_asa_message(111010, body, appliance=APPLIANCE_NAME)])
