# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: FortiGate Configuration File Downloaded
# RTA: fortigate_configuration_file_downloaded.py
# Description: Sends a synthetic FortiGate system event for an administrator
#              downloading the device configuration. Point this RTA at an
#              Elastic Agent Fortinet FortiGate integration listener; the
#              listener selects the fortinet_fortigate.log data stream.
#
#              The raw message shape is derived from Fortinet integration
#              fixtures and ingest pipelines pinned at:
#              elastic/integrations@4c0916e8faf8172686249fa33308f1f9e8f077aa

from datetime import UTC, datetime

from . import OSType, RuleMetadata, register_code_rta
from ._syslog import send_syslog

APPLIANCE_NAME = "fortigate-rta"
DEVICE_ID = "FGVMTM0000000001"
ADMIN_USER = "rta-admin"
ADMIN_SOURCE_IP = "192.0.2.50"
DEVICE_IP = "192.0.2.1"
EVENT_CODE = "0100032095"


def build_fortigate_configuration_download_message(timestamp: datetime | None = None) -> str:
    """Build the FortiGate key-value event consumed by the pinned pipeline."""
    event_time = (timestamp or datetime.now(UTC)).astimezone(UTC)
    event_nanoseconds = int(event_time.timestamp() * 1_000_000_000)
    return (
        f"<189>date={event_time:%Y-%m-%d} time={event_time:%H:%M:%S} "
        f'devname="{APPLIANCE_NAME}" devid="{DEVICE_ID}" eventtime={event_nanoseconds} tz="+0000" '
        f'logid="{EVENT_CODE}" type="event" subtype="system" level="notice" vd="root" '
        f'logdesc="Configuration file downloaded" sn="0" user="{ADMIN_USER}" '
        f'ui="https({ADMIN_SOURCE_IP})" method="https" srcip={ADMIN_SOURCE_IP} dstip={DEVICE_IP} '
        f'action="download" status="success" '
        f'msg="Administrator {ADMIN_USER} downloaded the configuration file"'
    )


@register_code_rta(
    id="fa1ae12e-f5b8-479f-8462-8247f0d69c02",
    name="fortigate_configuration_file_downloaded",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="b7e2a04d-4f8a-4e12-8c9a-1d5e6f7a8b9c",
            name="FortiGate Configuration File Downloaded",
        )
    ],
    techniques=["T1602", "T1602.002", "T1552", "T1552.001"],
)
def main() -> None:
    """Send one FortiGate configuration-download event."""
    send_syslog([build_fortigate_configuration_download_message()])
