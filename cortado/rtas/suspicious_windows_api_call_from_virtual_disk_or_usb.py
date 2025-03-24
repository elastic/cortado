
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="c0954a8c-3bc9-4ef5-9e41-3823de3ddce9",
    name="suspicious_windows_api_call_from_virtual_disk_or_usb",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="9d5f965f-6f77-45df-9733-8707e40d1d71", name="Suspicious Windows API Call from Virtual Disk or USB")
    ],
    techniques=['T1055'],
    sample_hash="272ccc3ddefa67f5069fb20a2aaf5f8113239c3fccd8e02bb62d9574143de59d",
)
