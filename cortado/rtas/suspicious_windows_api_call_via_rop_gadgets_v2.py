
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="b387b2c7-7976-4474-bd24-75df6ecc3ae6",
    name="suspicious_windows_api_call_via_rop_gadgets_v2",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="9bc5d4cd-5748-4425-a4f3-7a704a11029d", name="Suspicious Windows API Call via ROP Gadgets v2")
    ],
    techniques=['T1055'],
    sample_hash="b21ab459e9dc1ce72ce5e54d7bc2768da44d6db99894ee29714495382280824a",
)
