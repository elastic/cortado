# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5282c9a4-4ce9-48b8-863a-ff453143635a",
    name="linux_persistence_kworker_file_creation",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="ae343298-97bc-47bc-9ea2-5f2ad831c16e", name="Suspicious File Creation via kworker")],
    techniques=["T1547", "T1014"],
)
def main() -> None:
    masquerade = "/tmp/kworker"
    source = _common.get_resource_path("bin/create_file.elf")
    _common.copy_file(source, masquerade)

    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "/tmp/evil"]

    log.info("Simulating file creation activity..")
    _ = _common.execute_command(commands, timeout_secs=5)
    log.info("File creation simulation successful!")
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("RTA completed!")
