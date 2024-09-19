# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: COM Hijack via Script Object
# RTA: scrobj_com_hijack.py
# ATT&CK: T1122
# Description: Modifies the Registry to create a new user-defined COM broker, "scrobj.dll".

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ac739578-c978-429f-9454-0bbe82f993f4",
    name="scrobj_com_hijack",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="16a52c14-7883-47af-8745-9357803f0d4c", name="Component Object Model Hijacking")],
    techniques=["T1546"],
)
def main():
    key = "SOFTWARE\\Classes\\CLSID\\{00000000-0000-0000-0000-0000DEADBEEF}"
    subkey = "InprocServer32"
    value = ""
    scrobj = "C:\\WINDOWS\\system32\\scrobj.dll"
    key_path = key + "\\" + subkey

    with _common.temp_registry_value(_const.REG_HKCU, key_path, value, scrobj, pause=True):
        pass
