# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential Cisco ISE Logging Configuration Impairment
# RTA: cisco_ise_logging_configuration_impaired.py
# Description: Sends synthetic Cisco ISE administrative-audit events for
#              disabled local category logging, logging-target deletion, and
#              one-day local log retention.
#
#              Point this RTA at an Elastic Agent Cisco ISE integration
#              listener. The listener, not the sender, selects the data stream.

from datetime import UTC, datetime, timedelta

from . import OSType, RuleMetadata, register_code_rta
from ._cisco_syslog import build_ise_message, send_syslog

APPLIANCE_NAME = "ise-rta"
ADMIN_USER = "rta-admin"
ADMIN_SOURCE_IP = "192.0.2.50"
LOG_TARGET_NAME = "rta-syslog-target"
AUDIT_CATEGORY = "CISE_Administrative_and_Operational_Audit"


def _build_messages() -> list[str]:
    event_time = datetime.now(UTC)
    local_logging_disabled = build_ise_message(
        category=AUDIT_CATEGORY,
        message_id=1,
        event_code=52001,
        description="Configuration-Changes: Changed configuration",
        details=(
            "ConfigVersionId=1, FailureFlag=false, RequestResponseType=initial, "
            f"AdminInterface=GUI, AdminIPAddress={ADMIN_SOURCE_IP}, AdminName={ADMIN_USER}, "
            "ConfigChangeData=Object modified:\\, Log Severity Level = INFO\\,"
            f"Local Logging = disable\\,Assigned Targets = {{{LOG_TARGET_NAME}}}, "
            "ObjectType=UPSCategory, ObjectName=Administrative Audit, "
            'OperationMessageText=LoggingCategories "Administrative and Operational Audit" '
            "has been edited successfully."
        ),
        appliance=APPLIANCE_NAME,
        timestamp=event_time,
    )
    target_deleted = build_ise_message(
        category=AUDIT_CATEGORY,
        message_id=2,
        event_code=52002,
        description="Configuration-Changes: Deleted configuration",
        details=(
            f"ConfigVersionId=2, AdminInterface=GUI, AdminIPAddress={ADMIN_SOURCE_IP}, "
            f"AdminName={ADMIN_USER}, ConfigChangeData=object deleted: Name={LOG_TARGET_NAME}, "
            f"ObjectType=UPSLogTarget, ObjectName={LOG_TARGET_NAME}, Component=Administration"
        ),
        appliance=APPLIANCE_NAME,
        timestamp=event_time + timedelta(milliseconds=1),
    )
    one_day_retention = build_ise_message(
        category=AUDIT_CATEGORY,
        message_id=3,
        event_code=52001,
        description="Configuration-Changes: Changed configuration",
        details=(
            "ConfigVersionId=3, FailureFlag=false, RequestResponseType=initial, "
            f"AdminInterface=GUI, AdminIPAddress={ADMIN_SOURCE_IP}, AdminName={ADMIN_USER}, "
            "ConfigChangeData=Local Storage Period = 1 days, "
            "ObjectType=UPSLogSettings, ObjectName=LocalStore"
        ),
        appliance=APPLIANCE_NAME,
        timestamp=event_time + timedelta(milliseconds=2),
    )
    return [local_logging_disabled, target_deleted, one_day_retention]


@register_code_rta(
    id="35e0a75e-f714-4e3f-9376-073e8f0d1770",
    name="cisco_ise_logging_configuration_impaired",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="dde6b02e-641a-4ca2-8207-82090d988a31",
            name="Potential Cisco ISE Logging Configuration Impairment",
        )
    ],
    techniques=["T1562.001"],
)
def main() -> None:
    """Send all three positive Cisco ISE logging-impairment variants."""
    send_syslog(_build_messages())
