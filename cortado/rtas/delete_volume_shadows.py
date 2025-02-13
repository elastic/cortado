# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Volume Shadow Copy Deletion with vssadmin and wmic
# RTA: delete_volume_shadow.py
# signal.rule.name: Volume Shadow Copy Deletion via VssAdmin
# ELastic Detection: Volume Shadow Copy Deletion via WMIC
# ATT&CK: T1107
# Description: Uses both vssadmin.exe and wmic.exe to delete volume shadow copies.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ae6343cc-3b56-4f60-854f-7102db519ec4",
    name="delete_volume_shadows",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="dc9c1f74-dac3-48e3-b47f-eb79db358f57", name="Volume Shadow Copy Deletion via WMIC")],
    techniques=["T1490"],
)
def main():
    log.info("Deleting volume shadow copies...")
    _ = _common.execute_command(["vssadmin.exe", "delete", "shadows", "/for=c:", "/oldest", "/quiet"])
    # Create a volume shadow copy so that there is at least one to delete
    _ = _common.execute_command(["wmic.exe", "shadowcopy", "call", "create", "volume=c:\\"])
    _ = _common.execute_command(["wmic.exe", "shadowcopy", "delete", "/nointeractive"])
