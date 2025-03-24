
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="ce314672-2c1d-47a3-a5da-4d0b54352a70",
    name="self_service_persistence_by_an_unsigned_process",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="e5ad5d97-da99-4371-9611-b6dfa8e55e30", name="Self Service Persistence by an Unsigned Process")
    ],
    techniques=['T1543', 'T1543.003'],
    sample_hash="79dc900d0bfac9749b5ddb5d237b3d384769104ad22eeec29a30752263593f67",
)
