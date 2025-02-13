# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1bb39cea-8bf2-4b1f-a70e-69f6074a1fb4",
    name="network_connection_unusual_rundll32",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="2e708541-c6e8-4ded-923f-78a6c160987e", name="Unusual Network Connection via RunDLL32"),
    ],
    techniques=["T1055", "T1218", "T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/regsvr32.exe")

    binary = "rundll32.exe"
    _common.copy_file(EXE_FILE, binary)

    log.info("Making connection using fake rundll32.exe")
    _ = _common.execute_command(binary, shell=True)
    _common.remove_files([binary])
