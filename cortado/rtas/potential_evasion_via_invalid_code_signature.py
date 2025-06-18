# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="34587ca9-3adb-42e6-948c-d1f81dc12680",
    name="potential_evasion_via_invalid_code_signature",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f3f769b9-0695-49ed-ab6e-c8f199a7d2c8", name="Potential Evasion via Invalid Code Signature")
    ],
    techniques=['T1055', 'T1036'],
    sample_hash="fb68f4812303beb08bb62f4b54bde01c0c11220ec1aab78d71f76f42ada86cdf",
)
