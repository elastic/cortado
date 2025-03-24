
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="7f85402a-ed80-459d-9eeb-9e1a4a8150c8",
    name="network_activity_from_a_stomped_module",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="4388a77b-4ddf-4e15-8314-ecf96c77807a", name="Network Activity from a Stomped Module")
    ],
    techniques=['T1055'],
    sample_hash="966a6c9fd83512c580dfc9f8cf666361ba6f7491d296e707a29c4780e5825f3f",
)
