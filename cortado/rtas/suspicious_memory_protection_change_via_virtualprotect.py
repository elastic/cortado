
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="9af91d3f-099f-48dc-adcf-b5136934de86",
    name="suspicious_memory_protection_change_via_virtualprotect",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="8fcf2b81-8322-423b-a1b4-6bba722f599a", name="Suspicious Memory Protection Change via VirtualProtect")
    ],
    techniques=['T1055'],
    sample_hash="24ef9c8f66fb72058ce87b39819849c41facfb5c2ac8ac903ebf4277580fc7b4",
)
