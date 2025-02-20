# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="13fbcfdc-ba84-414b-aaa6-49b416806c8e",
    name="reg_run_key_asterisk",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="94d35931-5c48-49ed-8c18-d601c4f8aeaa", name="Registry Run Key Prefixed with Asterisk")
    ],
    techniques=["T1547"],
)
def main():
    log.info("Writing registry key")

    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    value = "*test"
    data = "test"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
