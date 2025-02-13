# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="be6619a2-324a-443b-9f23-2dc84733c847",
    name="child_w3wp",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="89c9c5a0-a136-41e9-8cc8-f21ef5ad894b", name="Suspicious Microsoft IIS Worker Descendant")
    ],
    techniques=["T1190", "T1059"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    w3wp = "C:\\Users\\Public\\w3wp.exe"
    _common.copy_file(EXE_FILE, w3wp)

    # Creating a high entropy file, and executing the rename operation
    _ = _common.execute_command([w3wp, "/c", "cmd.exe"], timeout_secs=10)
    _common.remove_file(w3wp)
