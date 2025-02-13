# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="086c6cae-22ac-47b6-bd24-85b33d8cf3a2",
    name="elevated_osascript_execution",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="f17c8dcf-d65f-479a-b047-3558233f774e", name="Elevated Apple Script Execution via Unsigned Parent"
        )
    ],
    siem_rules=[
        RuleMetadata(
            id="827f8d8f-4117-4ae4-b551-f56d54b9da6b", name="Apple Scripting Execution with Administrator Privileges"
        )
    ],
    techniques=["T1078", "T1548", "T1059"],
)
def main():
    # create masquerades
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute commands
    log.info("Launching fake osascript commands to mimic apple script execution")
    command = "osascript with administrator privileges"
    _ = _common.execute_command([masquerade, "childprocess", command], timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
