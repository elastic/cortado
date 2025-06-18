# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="fbcd275f-aeba-4297-a25a-cbe8fe596399",
    name="startup_persistence_from_backed_rwx_memory",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="15c48f2d-e461-40a9-accd-090a0863ea10", name="Startup Persistence from Backed RWX Memory")
    ],
    techniques=['T1547', 'T1547.001'],
    sample_hash="a30c4fc8b11cb71e7b91b955a1ac756daf4444bbf04d79d4f292953599e2abfd",
)
