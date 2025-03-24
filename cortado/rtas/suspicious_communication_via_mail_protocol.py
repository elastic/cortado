# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="adc67195-dd7a-41f5-a929-6ea25559a26a",
    name="suspicious_communication_via_mail_protocol",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="0898f7c9-f667-4db1-a1ce-ddbf61a32361", name="Suspicious Communication via Mail Protocol")
    ],
    techniques=['T1071', 'T1071.003', 'T1204', 'T1204.002'],
    sample_hash="afbf51cbceee0bb274325a6bbdeb87bcaadf086f26b97a4715a0345d2d20252e",
)
