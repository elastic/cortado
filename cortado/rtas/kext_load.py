# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c4ac8740-3dca-4550-831b-e03d21de581d",
    name="kext_load",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="de869aa1-c63a-451e-a953-7069ec39ba60", name="New System Kext File and Immediate Load via KextLoad"
        )
    ],
    techniques=["T1547", "T1547.006", "T1059", "T1059.004"],
)
def main():
    # create masquerades
    masquerade = "/tmp/mv"
    _common.create_macos_masquerade(masquerade)

    # Execute command"
    log.info("Launching fake commands load Kext file.")
    _ = _common.execute_command([masquerade, "/System/Library/Extensions/*.kext"], timeout_secs=10)
    _ = _common.execute_command(
        ["kextload", "test.kext"],
        timeout_secs=10,
    )

    # cleanup
    _common.remove_file(masquerade)
