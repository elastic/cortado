# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import _common, register_code_rta, OSType, RuleMetadata

log = logging.getLogger(__name__)


@register_code_rta(
    id="b88c08af-eee5-4683-a56a-36e91e6386d5",
    name="enumeration_linpeas",
    platforms=[OSType.MACOS, OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="92bb2a27-745b-4291-90a1-b7b654df1379", name="Privilege Escalation Enumeration via LinPEAS")
    ],
    siem_rules=[],
    techniques=["T1059"],
)
def main():
    masquerade = "/tmp/sed"
    if _common.get_current_os() == OSType.LINUX:
        source = _common.get_resource_path("bin/linux.ditto_and_spawn")
        _common.copy_file(source, masquerade)
    else:
        _common.create_macos_masquerade(masquerade)

    log.info("Executing fake sed command for LinPEAS behavior.")
    _ = _common.execute_command([masquerade, "testImPoSSssSiBlEeetest"], timeout_secs=5, shell=True)

    # cleanup
    _common.remove_file(masquerade)
