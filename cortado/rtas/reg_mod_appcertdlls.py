# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4c0e7d24-63d1-4888-9ea4-0d920ce3fe40",
    name="reg_mod_appcertdlls",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="513f0ffd-b317-4b9c-9494-92ce861f22c7", name="Registry Persistence via AppCert DLL")],
    techniques=["T1546", "T1546.009"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    key = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs"
    value = "RTA"
    data = "NotMalicious"

    with _common.temporary_reg(_common.HKLM, key, value, data):
        pass
