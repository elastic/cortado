# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c8efd8c9-b32c-482a-90ff-f2d366a2af45",
    name="eicar",
    platforms=[OSType.MACOS, OSType.LINUX, OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="c4539c79-9f55-4b36-b06f-8aff82563bca", name="Behavior Protection - EICAR")],
    techniques=["TA0002"],
)
def main():
    masquerade = "/tmp/bash"
    current_os = _common.get_current_os()
    if current_os in (OSType.MACOS, OSType.LINUX):
        if current_os == OSType.LINUX:
            source = _common.get_resource_path("bin/linux.ditto_and_spawn")
            _common.copy_file(source, masquerade)
        else:
            _common.create_macos_masquerade(masquerade)

        # Execute command
        log.info("Launching behavior diag test")
        _ = _common.execute_command([masquerade, "elastic-behavior-protection-eicar"], timeout_secs=10)

        # cleanup
        _common.remove_file(masquerade)
    else:
        cmd = "C:\\Windows\\System32\\cmd.exe"

        # Execute command
        log.info("Launching eicar test")
        _ = _common.execute_command([cmd, "/c", "echo", "elastic-behavior-protection-eicar"])
