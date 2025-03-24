# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="e8b32a35-de6f-4f22-a132-6e233f7eaf8d",
    name="image_hollow_from_unusual_stack",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="446e61bf-8370-45df-88ab-7b213ee653db", name="Image Hollow from Unusual Stack")
    ],
    techniques=['T1055'],
    sample_hash="966a6c9fd83512c580dfc9f8cf666361ba6f7491d296e707a29c4780e5825f3f",
)
