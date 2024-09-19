# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b434626c-4787-4967-9984-50c0db12692f",
    name="reg_mod_appinitdlls",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="d0e159cf-73e9-40d1-a9ed-077e3158a855", name="Registry Persistence via AppInit DLL")],
    techniques=["T1546", "T1546.010"],
)
def main():
    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    value = "AppInit_Dlls"
    data = "RTA"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
