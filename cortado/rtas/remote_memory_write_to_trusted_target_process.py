# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="36167273-a4c6-4c58-a608-71610e2690f9",
    name="remote_memory_write_to_trusted_target_process",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="5c6c166c-a894-4263-918a-c7632014a486", name="Remote Memory Write to Trusted Target Process")
    ],
    techniques=['T1055'],
    sample_hash="0301f0dc2a049a1967afa9e1c842a276436b3d370eef4ae163a1ef84c37181da",
)
