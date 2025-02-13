# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f2b4878b-34db-4673-8fde-81be3df7ab30",
    name="exec_odbcconf",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="1faebe83-38d7-4390-b6bd-9c6b851e47c4", name="Suspicious ImageLoad via ODBC Driver Configuration Program"
        )
    ],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    odbcconf = "C:\\Users\\Public\\odbcconf.exe"
    _common.copy_file(EXE_FILE, odbcconf)

    _ = _common.execute_command([odbcconf, "echo", "-a"], timeout_secs=10)
    _common.remove_files([odbcconf])
