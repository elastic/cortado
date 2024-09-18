# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4d7ce5b3-f8e4-434c-9caa-c7e133146b27",
    name="empire_stager",
    platforms=["macos", "linux"],
    endpoint_rules=[RuleMetadata(id="b7974ff6-82ff-4743-9e07-1c6901b1f0ea", name="Empire Stager Execution")],
    siem_rules=[],
    techniques=["T1132", "T1059"],
)
def main():
    masquerade = "/tmp/bash"
    if _common.CURRENT_OS == "linux":
        source = _common.get_resource_path("bin/linux.ditto_and_spawn")
        _common.copy_file(source, masquerade)
    else:
        _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake bash with base64 decode commands")
    _ = _common.execute_command(
        [masquerade, "exec(base64.b64decode*aW1wb3J0IHN5cztpbXBvcnQg)"],
        timeout_secs=10,
        kill=True,
    )

    # cleanup
    _common.remove_file(masquerade)
