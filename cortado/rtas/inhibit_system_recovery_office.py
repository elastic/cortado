# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="aa05a870-7075-42f9-a009-49aa75ea99fa",
    name="inhibit_system_recovery_office",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="d3588fad-43ae-4f2d-badd-15a27df72132", name="Inhibit System Recovery via Untrusted Parent Process"
        ),
        RuleMetadata(
            id="58a08390-e69d-4b32-9487-1d1ddb16ba09", name="Inhibit System Recovery via Microsoft Office Process"
        ),
    ],
    siem_rules=[],
    techniques=["T1490", "T1047", "T1566"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed.exe")

    binary = "winword.exe"
    _common.copy_file(EXE_FILE, binary)

    # Execute command
    log.info("Deleting shadow copies using vssadmin")
    _ = _common.execute_command(
        [binary, "/c", "vssadmin.exe", "delete", "shadows", "/all", "/quiet"],
        timeout_secs=5,
        kill=True,
    )

    _common.remove_files([binary])
