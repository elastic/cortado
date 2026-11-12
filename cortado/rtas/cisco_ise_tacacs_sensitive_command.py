# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Sensitive Cisco Device Command via ISE TACACS
# RTA: cisco_ise_tacacs_sensitive_command.py
# Description: Sends a synthetic Cisco ISE 3300 TACACS+ command-accounting
#              event for a privilege-level 15 command that disables logging.
#
#              Point this RTA at an Elastic Agent Cisco ISE integration
#              listener. The listener, not the sender, selects the data stream.

from . import OSType, RuleMetadata, register_code_rta
from ._cisco_syslog import build_ise_message, send_syslog

APPLIANCE_NAME = "ise-rta"
ADMIN_USER = "rta-admin"
NETWORK_DEVICE_NAME = "rta-router"
NETWORK_DEVICE_IP = "192.0.2.20"
REMOTE_ADDRESS = "198.51.100.20"
COMMAND = "no logging enable"


@register_code_rta(
    id="205cd667-a4e6-4f10-9617-de17ac102c92",
    name="cisco_ise_tacacs_sensitive_command",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="894e78a3-7690-42eb-af2e-2ffe4d8bb710",
            name="Sensitive Cisco Device Command via ISE TACACS",
        )
    ],
    techniques=["T1059.008"],
)
def main() -> None:
    """Send one privilege-level 15 ISE TACACS+ command-accounting event."""
    details = (
        f"ConfigVersionId=1, Device IP Address={NETWORK_DEVICE_IP}, "
        f"CmdSet=[ CmdAV={COMMAND} <cr> ], RequestLatency=1, "
        f"NetworkDeviceName={NETWORK_DEVICE_NAME}, Type=Accounting, Privilege-Level=15, "
        f"Service=Login, User={ADMIN_USER}, Port=tty0, Remote-Address={REMOTE_ADDRESS}, "
        "Authen-Method=TacacsPlus, AcctRequest-Flags=Stop, Service-Argument=shell, "
        "Response={AcctReply-Status=Success; }"
    )
    message = build_ise_message(
        category="CISE_TACACS_Accounting",
        message_id=1,
        event_code=3300,
        description="Tacacs-Accounting: TACACS+ Accounting with Command",
        details=details,
        appliance=APPLIANCE_NAME,
    )
    send_syslog([message])
