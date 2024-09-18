# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b39cddfa-97ec-41c7-8d4d-7cf0d5a7ddd4",
    name="exec_certoc_dll",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="6fcbf73f-4413-4689-be33-61b0d6bd0ffc", name="Suspicious ImageLoad via Windows CertOC")
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    certoc = "C:\\Users\\Public\\certoc.exe"
    _common.copy_file(EXE_FILE, certoc)

    _ = _common.execute_command([certoc, "-LoadDLL"], timeout_secs=1, kill=True)
    _common.remove_file(certoc)
