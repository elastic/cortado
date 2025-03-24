# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="6c264182-eaef-4776-aa52-4846fc0e79ff",
    name="network_connect_api_from_unbacked_memory",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="720e0265-03bc-4cb7-9116-7fad5ea9cdfc", name="Network Connect API from Unbacked Memory")
    ],
    techniques=['T1055'],
    sample_hash="eec61b37516a902f999d664590ae8538794f2bbf5f454be52c837cf52760dbfa",
)
