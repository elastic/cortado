
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="5c205bc5-b9b9-4afb-b93b-91927500f721",
    name="potential_remote_code_injection",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f1d05929-4271-4d39-9cae-05eab6d4efca", name="Potential Remote Code Injection")
    ],
    techniques=['T1055'],
    sample_hash="67f264aef12ee76e84254428afc9e489162b57f2f019dec7ec85c421d616a7ad",
)
