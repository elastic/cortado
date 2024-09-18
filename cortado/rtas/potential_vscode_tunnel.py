# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import os
import pathlib

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

@register_code_rta(
    id="fb5cd755-cc31-4142-969a-cd14d3142b36",
    name="potential_vscode_tunnel",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="aec74eb4-9618-42ff-96eb-2d13e6959d47", name="Potential VScode Remote Tunnel Established"),
    ],
    siem_rules=[],
    techniques=["T1059"],
)
def main() -> None:
    masquerade = "code_tunnel.json"
    working_dir = "/tmp/fake_folder/code"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")

    # Execute command
    log.info("Executing Fake commands to test Potential VScode Remote Tunnel Established")
    pathlib.Path(working_dir).mkdir(parents=True, exist_ok=True)
    os.chdir(working_dir)
    _common.copy_file(source, masquerade)

    # cleanup
    _common.remove_file(masquerade)
