
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="23d05e3a-f17a-433a-9018-6077c50cc98e",
    name="suspicious_ntdll_memory_write",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="7a23d763-4904-40f9-8169-0c49af65ad30", name="Suspicious NTDLL Memory Write")
    ],
    techniques=['T1055'],
    sample_hash="9f932b464d9cdf2675536a0d392210acdd14987ad018aea73ac34214a7a78ce4",
)
