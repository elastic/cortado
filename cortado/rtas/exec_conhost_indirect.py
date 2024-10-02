# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="32e926c2-2f33-4dd0-ac77-12545331d3e4",
    name="exec_conhost_indirect",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="4b61b37d-c569-444a-bafa-e29d221ee55c", name="Indirect Command Execution via Console Window Host"
        )
    ],
    techniques=["T1202"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    conhost = "C:\\Users\\Public\\conhost.exe"
    posh = "C:\\Users\\Public\\posh.exe"
    _common.copy_file(EXE_FILE, conhost)
    _common.copy_file(EXE_FILE, posh)

    _ = _common.execute_command([conhost, posh], timeout_secs=10)
    _common.remove_files([conhost, posh])
