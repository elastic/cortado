# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="44f50c16-742b-427a-aee7-6d812f908814",
    name="microsoft_common_language_runtime_loaded_from_suspicious_memory",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="ad2c6fcc-89d3-4939-85d9-d7114d6bbf14", name="Microsoft Common Language Runtime Loaded from Suspicious Memory")
    ],
    techniques=['T1055'],
    sample_hash="44788f535787ccc40ce79b30e4191e48986c2d40025cc0d55c32668b52acb3fa",
)
