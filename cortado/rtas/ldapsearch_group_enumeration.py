# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="370c3432-65f5-4068-b879-916bc1297c60",
    name="ldapsearch_group_enumeration",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="6e9b351e-a531-4bdc-b73e-7034d6eed7ff", name="Enumeration of Users or Groups via Built-in Commands"
        )
    ],
    techniques=["T1069", "T1087"],
)
def main():
    masquerade = "/tmp/ldapsearch"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake ldapsearch commands to mimic user or group enumeration")
    _ = _common.execute_command([masquerade, "testing"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
