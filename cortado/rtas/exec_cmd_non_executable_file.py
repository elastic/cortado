# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="0630610d-a9ae-47df-9e2f-e7f393972f1e",
    name="exec_cmd_non_executable_file",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="c0770406-7ede-4049-a7a1-999c15fb60bd", name="Execution of Non-Executable File via Shell")
    ],
    siem_rules=[],
    techniques=["T1036", "T1059", "T1059.004"],
)
def main():
    _common.log("Executing bash on unexecutable file.")
    with _common.temporary_file("testing", "/*.txt"):
        _common.execute(["/bin/bash", "/*.txt"])
