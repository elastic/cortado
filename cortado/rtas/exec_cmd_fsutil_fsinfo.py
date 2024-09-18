# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="904cae88-f6bf-4585-b779-2451ce4b6b1b",
    name="exec_cmd_fsutil_fsinfo",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="0c7ca5c2-728d-4ad9-b1c5-bbba83ecb1f4", name="Peripheral Device Discovery")],
    techniques=["T1120"],
)
def main():
    fsutil = "C:\\Windows\\System32\\fsutil.exe"

    # Execute command
    _ = _common.execute_command([fsutil, "fsinfo", "drives"], timeout_secs=10)
