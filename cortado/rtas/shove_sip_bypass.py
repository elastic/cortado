# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1796555f-921a-459f-9661-0d94cf90fe81",
    name="shove_sip_bypass",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="7dea8cfc-92db-4081-9a5d-85ead8cedd5f", name="Potential SIP Bypass via the ShoveService")
    ],
    techniques=["T1068"],
)
def main():
    masquerade = "/tmp/sh"
    _common.create_macos_masquerade(masquerade)

    log.info("Executing shove processes to mimic sip bypass.")
    command = "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/Resources/shove -x"
    _ = _common.execute_command([masquerade, "childprocess", command],) timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
