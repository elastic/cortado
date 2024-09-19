# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import platform

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f1321e5c-101d-4b03-8f0c-6cf8bda174ec",
    name="dylib_injection",
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
    target_bin = _common.get_resource_path("bin", name)
    _ = _common.execute_command([f"DYLD_INSERT_LIBRARIES={dylib}", target_bin, "5"], shell=True)
