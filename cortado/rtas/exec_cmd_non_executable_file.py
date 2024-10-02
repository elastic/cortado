# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0630610d-a9ae-47df-9e2f-e7f393972f1e",
    name="exec_cmd_non_executable_file",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="c0770406-7ede-4049-a7a1-999c15fb60bd", name="Execution of Non-Executable File via Shell")
    ],
    techniques=["T1036", "T1059", "T1059.004"],
)
def main():
    log.info("Executing bash on unexecutable file.")
    with _common.file_with_data("/*.txt", "testing"):
        _ = _common.execute_command(["/bin/bash", "/*.txt"])
