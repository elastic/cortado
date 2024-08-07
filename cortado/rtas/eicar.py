# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="c8efd8c9-b32c-482a-90ff-f2d366a2af45",
    name="eicar",
    platforms=["macos", "linux", "windows"],
    endpoint_rules=[RuleMetadata(id="c4539c79-9f55-4b36-b06f-8aff82563bca", name="Behavior Protection - EICAR")],
    siem_rules=[],
    techniques=["TA0002"],
)
def main():
    masquerade = "/tmp/bash"
    if _common.CURRENT_OS in ["linux", "macos"]:
        if _common.CURRENT_OS == "linux":
            source = _common.get_path("bin", "linux.ditto_and_spawn")
            _common.copy_file(source, masquerade)
        else:
            _common.create_macos_masquerade(masquerade)

        # Execute command
        _common.log("Launching behavior diag test")
        _common.execute([masquerade, "elastic-behavior-protection-eicar"], timeout=10, kill=True)

        # cleanup
        _common.remove_file(masquerade)
    else:
        cmd = "C:\\Windows\\System32\\cmd.exe"

        # Execute command
        _common.log("Launching eicar test")
        _common.execute([cmd, "/c", "echo", "elastic-behavior-protection-eicar"])
