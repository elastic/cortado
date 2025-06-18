# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="b4245c29-ed9a-4059-a145-4a1303ff2b04",
    name="unusual_windows_system_service_disabled",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="7c44cfc6-d336-400e-9cc1-2417dfb5c00a", name="Unusual Windows System Service Disabled")
    ],
    techniques=['T1112', 'T1562', 'T1562.001'],
    sample_hash="1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b",
)
