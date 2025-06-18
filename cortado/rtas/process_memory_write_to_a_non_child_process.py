# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="93f0485e-9fc8-4ac2-9bee-e2604a7b0bfa",
    name="process_memory_write_to_a_non_child_process",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="fa2e2435-d285-485e-9890-dff92cb78ab7", name="Process Memory Write to a Non Child Process")
    ],
    techniques=['T1055'],
    sample_hash="67f264aef12ee76e84254428afc9e489162b57f2f019dec7ec85c421d616a7ad",
)
