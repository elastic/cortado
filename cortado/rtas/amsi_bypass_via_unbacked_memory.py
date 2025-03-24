
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="2b4f1347-749e-4acd-a422-5d66bc994998",
    name="amsi_bypass_via_unbacked_memory",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="06516087-9305-482b-af9a-92f4386d2f19", name="AMSI Bypass via Unbacked Memory")
    ],
    techniques=['T1562', 'T1562.001'],
    sample_hash="aa31279da8b6c8dbefe9d3d6c423f3f785fd13ab8539839c73d13e9580ebe22c",
)
