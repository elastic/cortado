# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="425ba45e-10eb-4067-93f4-95701d26da3d",
    name="suspicious_mining_process",
    platforms=[OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="fbf9342e-3d1e-4fba-a828-92fa0fb4d21b", name="Suspicious Mining Process Events")],
    techniques=["T1059", "T1059.004"],
)
def main():
    masquerade = "/tmp/systemctl"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching fake builtin commands for disabling _common mining services by name")
    command = "start"
    command1 = "apache4.service"
    _ = _common.execute_command([masquerade, command, command1], timeout_secs=10)
    # cleanup
    _common.remove_file(masquerade)
