# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d2c9baa4-6dda-46ff-acaa-f70ac0d3391b",
    name="linux_python_hidden_file_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="b25ec4e7-34f1-40c2-b683-bbf1dcdd84e5", name="Linux Hidden Folder or File Execution via Python")
    ],
    techniques=["T1059"],
)
def main():
    masquerade = "/tmp/python"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "python", "/dev/shm/.foo"]

    # Execute command
    log.info("Launching fake command to simulate Python hidden execution")
    _ = _common.execute_command([*commands], timeout_secs=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
