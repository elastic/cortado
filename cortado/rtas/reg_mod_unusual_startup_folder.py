# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4ac771ca-5095-4a1b-ac6a-e2b714be8ccc",
    name="reg_mod_unusual_startup_folder",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="377aad38-24e0-4dd7-93c2-bd231cb749e3", name="Unusual Startup Shell Folder Modification")
    ],
    techniques=["T1547", "T1547.001", "T1112"],
)
def main():
    log.info("Temp Registry mod: Common Startup Folder")

    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
    value = "Common Startup"
    data = "Test"

    with _common.temp_registry_value(_const.REG_HKLM, key, value, data):
        pass
