# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="eddbcd95-2922-46e4-b356-86d3bc8aeadc",
    name="dsenableroot_account",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="cc2fd2d0-ba3a-4939-b87f-2901764ed036", name="Attempt to Enable the Root Account")],
    techniques=[""],
)
def main():
    masquerade = "/tmp/dsenableroot"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake dsenableroot commands to mimic enabling root accounts.")
    _ = _common.execute_command([masquerade], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
