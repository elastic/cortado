# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4bb0b65e-8e78-4680-ab37-d6c0723f97a9",
    name="schtasks_xml_masqueraded",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="1efc0496-106b-4c09-b99b-91cdd17ba7b3",
            name="Suspicious Scheduled Task Creation via Masqueraded XML File",
        )
    ],
    siem_rules=[],
    techniques=["T1053", "T1036"],
)
def main():
    # Execute Command
    log.info("Executing command to simulate the task creation (This will not create a task)")
    _ = _common.execute_command(["schtasks.exe", "/CREATE", "/XML", "update", "/TN", "Test", "/F"])
