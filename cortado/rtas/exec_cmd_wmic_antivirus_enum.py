# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="d123ee22-aa28-4dcd-9c3b-5be047eb6eff",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="6ea55c81-e2ba-42f2-a134-bccf857ba922", name="Security Software Discovery using WMIC")],
    techniques=["T1518", "T1518.001"],
)
def main():
    wmic = "C:\\Windows\\System32\\wbem\\WMIC.exe"

    # Execute command
    _common.execute(
        [wmic, "/namespace:\\\\root\\SecurityCenter2", "Path", "AntiVirusProduct", "get", "displayname"], timeout=10
    )
