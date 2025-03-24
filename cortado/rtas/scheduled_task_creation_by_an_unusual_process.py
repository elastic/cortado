# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="67e1e8ad-b03a-4a54-a557-1a0f7d1df09b",
    name="scheduled_task_creation_by_an_unusual_process",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="cb5fdbe3-84fa-4277-a967-1ffc0e8d3d25", name="Scheduled Task Creation by an Unusual Process")
    ],
    techniques=['T1053', 'T1053.005'],
    sample_hash="6c2e0ad04040327910085d9ca58be3fbe423e5f15c1fe982c4ec41b48cb39c71",
)
