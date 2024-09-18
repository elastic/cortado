# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="712509fa-5326-4ebc-bb1e-82ddf28e8baa",
    name="reg_mod_enableat",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="9aa0e1f6-52ce-42e1-abb3-09657cee2698", name="Scheduled Tasks AT Command Enabled")],
    techniques=["T1562", "T1562.001"],
)
def main():
    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Configuration"
    value = "EnableAt"
    data = 1

    with _common.temporary_reg(_common.HKLM, key, value, data, data_type="dword"):
        pass
