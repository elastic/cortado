
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="8e1ebc30-a8c4-43c5-9727-f6202efcc6de",
    name="suspicious_executable_heap_allocation",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="4d21b212-1046-41fc-98f1-b4c175594fb2", name="Suspicious Executable Heap Allocation")
    ],
    techniques=['T1055'],
    sample_hash="3304e74d8e4b0ce5732beb1afd56e2858f63fa390cc963ff6f53118864bb8e95",
)
