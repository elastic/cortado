# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="65ae1bcd-0b1c-4992-97c3-f40b0f92deb1",
    name="office_child_process",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="66da12b1-ac83-40eb-814c-07ed1d82b7b9", name="Suspicious macOS MS Office Child Process")
    ],
    techniques=["T1566"],
)
def main():
    # create masquerades
    masquerade = "/tmp/Microsoft Word"
    masquerade2 = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)
    _common.create_macos_masquerade(masquerade2)

    log.info("Executing fake Microsoft commands to mimic suspicious child processes.")
    _ = _common.execute_command([masquerade, "childprocess", masquerade2], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
