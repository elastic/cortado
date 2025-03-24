
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="b7fe9bcd-bc6f-4629-830b-c6ab4bf98597",
    name="suspicious_dns_lookup_by_remote_utilities_rmm",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="ff6e6c37-8048-4b94-8c83-bb9919081caf", name="Suspicious DNS Lookup by Remote Utilities RMM")
    ],
    techniques=['T1219'],
    sample_hash="5ee0c66e6c00f98587b262e43d8e922a1f49c2490aaa543cd837a01e7e42a0f3",
)
