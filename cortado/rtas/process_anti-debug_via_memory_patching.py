# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="5110c22c-f37c-4097-a78d-eb70a448ae37",
    name="process_anti-debug_via_memory_patching",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="4db10fd9-e219-4566-9388-8e9a0b7ac7a9", name="Process Anti-Debug via Memory Patching")
    ],
    techniques=['T1574'],
    sample_hash="b663833709691d3f95e434a750129c56564f6463932a66c91c0bb73564072d26",
)
