# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c3be0d35-069b-4b2b-ab92-63530e8c23f7",
    name="exec_curl_output",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="336ada1c-69f8-46e8-bdd2-790c85429696", name="Ingress Tool Transfer via CURL")],
    siem_rules=[],
    techniques=[""],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    curl = "C:\\Users\\Public\\curl.exe"
    _common.copy_file(EXE_FILE, curl)

    # Execute command
    _ = _common.execute_command([curl, "-o"], timeout_secs=10)

    _common.remove_file(curl)
