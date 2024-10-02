# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import platform

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="62eb4521-cfb8-4fb8-bc6d-792fe57273b7",
    name="binary_masquerade",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="4154c8ce-c718-4641-80db-a6a52276f1a4", name="Potential Binary Masquerading via Invalid Code Signature"
        )
    ],
    techniques=["T1036"],
)
def main():
    if platform.processor() == "arm":
        name = "com.apple.sleep_arm"
    else:
        name = "com.apple.sleep_intel"
    path = _common.get_resource_path(f"bin/{name}")
    _ = _common.execute_command([path, "5"])
