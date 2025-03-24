
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="1b2ff509-3c17-47b7-a2c5-8a0293343b75",
    name="writeprocessmemory_via_indirect_random_syscall",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="20106fed-9cb6-41ca-8ca2-ebf55da5fa18", name="WriteProcessMemory via Indirect Random Syscall")
    ],
    techniques=['T1055', 'T1036'],
    sample_hash="6c4a8bd310ce4f1146d84ca455a560fd082e7d22d8b8c772cef5ce89f68e3191",
)
