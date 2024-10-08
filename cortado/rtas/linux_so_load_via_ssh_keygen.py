# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5c520396-4951-4763-8512-a53545bcff9c",
    name="linux_so_load_via_ssh_keygen",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="cc29bf55-8d7f-45df-b8fe-212968c8951c", name="Linux Shared Object Load via SSH-Keygen")
    ],
    techniques=["T1574"],
)
def main():
    masquerade = "/tmp/ssh-keygen"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "-D", "foo"]

    # Execute command
    log.info("Launching fake command to simulate ssh-keygen shared object load")
    _ = _common.execute_command(commands, timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
