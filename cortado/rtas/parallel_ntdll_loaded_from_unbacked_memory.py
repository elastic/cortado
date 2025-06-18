# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="40944110-6966-4e9c-aef0-d7fe1093b87b",
    name="parallel_ntdll_loaded_from_unbacked_memory",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="69267bb2-e2d9-4621-9bf6-064ac885e49c", name="Parallel NTDLL Loaded from Unbacked Memory")
    ],
    techniques=['T1055'],
    sample_hash="81e4808bcd2b11a4fd3b23668882628bcbdce55c62009daa4b97b15e421e6d13",
)
