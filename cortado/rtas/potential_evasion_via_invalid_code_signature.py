
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="8e687b13-1146-4723-aa28-236d68bf85cf",
    name="potential_evasion_via_invalid_code_signature",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f3f769b9-0695-49ed-ab6e-c8f199a7d2c8", name="Potential Evasion via Invalid Code Signature")
    ],
    techniques=['T1055', 'T1036'],
    sample_hash="60c38c0cc5461a5698f05dad6f5715f62e2f8168caa8a81131686c888681fc03",
)
