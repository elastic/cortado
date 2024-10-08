# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9b0bbe6d-2116-4327-930b-51e3e5097487",
    name="linux_hack_tool",
    platforms=[OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="3337a10c-e950-4827-a44e-96a688fba221", name="Potential Linux Hack Tool Launched")],
    siem_rules=[RuleMetadata(id="1df1152b-610a-4f48-9d7a-504f6ee5d9da", name="Potential Linux Hack Tool Launched")],
)
def main():
    masquerade = "/tmp/crackmapexec"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching fake command to simulate a CME process")
    _ = _common.execute_command(masquerade, shell=True, timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
