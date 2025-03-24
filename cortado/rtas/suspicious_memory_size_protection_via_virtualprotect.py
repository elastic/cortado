
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="0ca239bf-0d7d-40d9-9941-bfffb4505d49",
    name="suspicious_memory_size_protection_via_virtualprotect",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="c771303c-a200-4df3-bb76-3e5f87a18438", name="Suspicious Memory Size Protection via VirtualProtect")
    ],
    techniques=['T1055'],
    sample_hash="7ee450ffaf282d0d9982c64d5e45d80d6a5ab8d5d1fd9038066e1c36d8292776",
)
