# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ac51c9f0-d8ea-4ee1-9371-f368aab884e9",
    name="linux_hidden_file_mount",
    platforms=[OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="5b544dbb-2c66-42cd-a4ee-8d1e5afe9903", name="Linux Hidden File Mounted")],
    techniques=["T1211", "T1059"],
)
def main():
    masquerade = "/tmp/mount"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "/media/.foo"]

    # Execute command
    log.info("Launching fake command to simulate hidden file mount")
    _ = _common.execute_command([*commands], timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
