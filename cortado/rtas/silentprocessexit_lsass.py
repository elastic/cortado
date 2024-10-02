# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="bf2f893a-513a-41ea-9170-2c9b08a2a55f",
    name="silentprocessexit_lsass",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="28969fe6-0ebe-4442-b40c-dbe9b4234f5e", name="LSA Dump via SilentProcessExit")],
    techniques=["T1003"],
)
def main():
    log.info("Temporarily creating LSA SilentProcessExit reg key...")

    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"
    value = "lsass.exe"
    data = "0"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
