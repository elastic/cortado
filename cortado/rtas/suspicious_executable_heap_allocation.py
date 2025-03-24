# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="677ae39b-b3b8-4331-9d5d-87265d6ceeb4",
    name="suspicious_executable_heap_allocation",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="4d21b212-1046-41fc-98f1-b4c175594fb2", name="Suspicious Executable Heap Allocation")
    ],
    techniques=['T1055'],
    sample_hash="db5e626fd6a1c8735888aeec339f3c8cc6150ff55afd39591ac7ebc16e341b6f",
)
