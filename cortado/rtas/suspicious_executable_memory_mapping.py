# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="5466965c-e2e4-43d4-94bd-5605c7fc1802",
    name="suspicious_executable_memory_mapping",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="20a1f655-498a-4a73-8793-9f7ed14b9601", name="Suspicious Executable Memory Mapping")
    ],
    techniques=['T1055'],
    sample_hash="8cea17eff24495134a3e6389071ed05d067057fff645ed688af65209cd913890",
)
