
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="bc02929d-6aa5-4b36-8086-3ddff099508f",
    name="potential_crypto_mining_activity",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="fe082539-a528-4453-ac19-34d57f2f7730", name="Potential Crypto Mining Activity")
    ],
    techniques=['T1496'],
    sample_hash="af94ddf7c35b9d9f016a5a4b232b43e071d59c6beb1560ba76df20df7b49ca4c",
)
