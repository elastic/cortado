# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="61631236-50c4-4c93-af2e-cf5f57e4f1af",
    name="suspicious_netsupport_execution",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="ad53a366-161a-4fa7-a75a-cc00658a767f", name="Suspicious NetSupport Execution")
    ],
    techniques=['T1219'],
    sample_hash="123bb52151b701d54695fb9ff3aeebee55542b71b49051f34dc2808ae5e59f17",
)
