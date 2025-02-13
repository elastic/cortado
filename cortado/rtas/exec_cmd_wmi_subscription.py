# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="3c2c32fd-0856-4fc9-8a2d-81ed85e568b0",
    name="exec_cmd_wmi_subscription",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="9b6813a1-daf1-457e-b0e6-0bb4e55b8a4c", name="Persistence via WMI Event Subscription")],
    techniques=["T1546", "T1546.003"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    wmic = "C:\\Users\\Public\\wmic.exe"
    _common.copy_file(EXE_FILE, wmic)

    _ = _common.execute_command([wmic, "/c", "echo", "create", "ActiveScriptEventConsumer"], timeout_secs=5)
    _common.remove_files([wmic])
