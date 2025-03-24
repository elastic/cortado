# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="280dd2ab-7d13-4ec8-960c-cb5b7ba15277",
    name="suspicious_null_terminated_call_stack",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="a4684714-f605-4944-98de-e593246faf15", name="Suspicious Null Terminated Call Stack")
    ],
    techniques=['T1036', 'T1055'],
    sample_hash="966a6c9fd83512c580dfc9f8cf666361ba6f7491d296e707a29c4780e5825f3f",
)
