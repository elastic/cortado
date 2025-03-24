# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="d470e747-0ff5-496d-9998-79730d69af02",
    name="remote_process_injection_via_mapping",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="95c534ee-1a49-4a35-bea2-2853f2737a17", name="Remote Process Injection via Mapping")
    ],
    techniques=['T1055'],
    sample_hash="ac381e891cda88d95c3402a58a256a52f1ff4e4fd0f4803f4d4ddd43691dd81f",
)
