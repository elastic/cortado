# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="be090f8e-dc7b-41eb-9c7e-74a0aed0dad1",
    name="eggshell_backdoor",
    platforms=[OSType.MACOS, OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="feed7842-34a6-4764-b858-6e5ac01a5ab7", name="EggShell Backdoor Execution")],
    siem_rules=[RuleMetadata(id="41824afb-d68c-4d0e-bfee-474dac1fa56e", name="EggShell Backdoor Execution")],
    techniques=["T1059"],
)
def main():
    masquerade = "/tmp/eggshell"
    if _common.get_current_os() == OSType.LINUX:
        source = _common.get_resource_path("bin/linux.ditto_and_spawn")
        _common.copy_file(source, masquerade)
    else:
        _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake commands for EggShell backdoor behavior")
    _ = _common.execute_command([masquerade, "eyJkZWJ1ZyI6test"], timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
