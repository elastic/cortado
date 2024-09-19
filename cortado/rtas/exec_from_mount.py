# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="21d1d048-b8c9-4b6d-9748-44f8af1b444d",
    name="exec_from_mount",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="87def154-004d-4d3a-8224-591e41804454", name="Shell Script Execution from abnormal Volume Mount Path"
        )
    ],
    techniques=["T1059", "T1059.004"],
)
def main():
    masquerade = "/Volumes/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching bash commands to simulate execution from mounted volume")
    _ = _common.execute_command([masquerade, "/Volumes/*/Contents/*"], timeout_secs=10)
