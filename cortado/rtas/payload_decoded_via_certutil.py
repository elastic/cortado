
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="54852fea-dad7-4bbd-9ba5-a05435198ac1",
    name="payload_decoded_via_certutil",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="dbc72ac5-a004-45de-916d-e8aac82c4789", name="Payload Decoded via CertUtil")
    ],
    techniques=['T1027', 'T1140'],
    sample_hash="24f65e496692a64157011ed08648a853312526299131e4f819376889ff94876d",
)
