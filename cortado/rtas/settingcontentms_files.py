# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Abusing SettingContent-ms Files
# RTA: settingcontentms_files.py
# signal.rule.name: Potential Modification of Accessibility Binaries
# signal.rule.name: Local Service Commands
# ATT&CK: T1193, T1204, T1064
# Description: SettingContent-ms file written to specific path or by risky process

import logging
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="7dea9748-dcac-49a9-8909-bd1f5590e508",
    name="settingcontentms_files",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="7405ddf1-6c8e-41ce-818f-48bea6bcaed8", name="Potential Modification of Accessibility Binaries")
    ],
    techniques=["T1546"],
)
def main():
    # Write to AppData\Local\
    _ = _common.execute_command(["cmd", "/c", "echo", "test", ">", "%APPDATA%\\test.SettingContent-ms"])
    time.sleep(1)
    _ = _common.execute_command(["cmd", "/c", "del", "%APPDATA%\\test.SettingContent-ms"])
