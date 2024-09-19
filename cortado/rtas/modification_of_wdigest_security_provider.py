# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="878ffa93-dea6-48f8-9441-e199bc23ec6b",
    name="modification_of_wdigest_security_provider",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="d703a5af-d5b0-43bd-8ddb-7a5d500b7da5", name="Modification of WDigest Security Provider")
    ],
    techniques=["T1003"],
)
def main():
    key = "System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
    value = "UseLogonCredential"
    data = 1

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data, data_type="dword"):
        pass
