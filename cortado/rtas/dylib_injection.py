# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import platform
from . import _common


@register_code_rta(
    id="f1321e5c-101d-4b03-8f0c-6cf8bda174ec",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="2df75424-4106-43c5-8fea-f115e18588da", name="Collect DIAG Dylib Load Event"),
        RuleMetadata(
            id="246741d4-3eee-4fbb-beec-53ef562c62c3", name="Dylib Injection via Process Environment Variables"
        ),
        RuleMetadata(
            id="4154c8ce-c718-4641-80db-a6a52276f1a4", name="Potential Binary Masquerading via Invalid Code Signature"
        ),
    ],
    siem_rules=[],
    techniques=["T1574", "T1574.006"],
)
def main():
    if platform.processor() == "arm":
        name = "com.apple.sleep_arm"
        dylib = "inject_arm.dylib"
    else:
        name = "com.apple.sleep_intel"
        dylib = "inject_intel.dylib"
    target_bin = _common.get_path("bin", name)
    _common.execute([f"DYLD_INSERT_LIBRARIES={dylib}", target_bin, "5"], kill=True, shell=True)
