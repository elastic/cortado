# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="54041e42-7a4b-417e-ac40-cd50c7085e48",
    name="exec_from_python",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="d8cbba0d-7275-4bcd-be22-79ee6fea2951", name="Suspicious Python Package Child Process Execution"
        )
    ],
    techniques=["T1059", "T1059.004", "T1059.006"],
)
def main():
    # test_file = "/tmp/test.txt"
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching bash commands to mimic python package execution")
    parent_args = "*/lib/python*/site-packages/*"
    _ = _common.execute_command([masquerade, "childprocess", parent_args, "-c"], timeout_secs=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
