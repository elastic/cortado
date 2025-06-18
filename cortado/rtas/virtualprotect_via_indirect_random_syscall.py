# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="d50d61c8-9e1c-4afa-b281-0f87ecf38b64",
    name="virtualprotect_via_indirect_random_syscall",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="2cb8bc8c-8eb7-418e-bb94-016460f8c6e1", name="VirtualProtect via Indirect Random Syscall")
    ],
    techniques=['T1055', 'T1036'],
    sample_hash="670a5d207b3fb79701916bc3a1a25a18b48daba0171b49b6675d3174cff11f43",
)
