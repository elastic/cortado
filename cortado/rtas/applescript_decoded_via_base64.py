# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="d9ff37e5-76c5-4f42-9f68-6814346b3c11",
    name="applescript_decoded_via_base64",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="9602ed93-b5cf-4397-ba37-6e752082847c",
            name="AppleScript decoded via Base64",
        ),
    ],
    techniques=["T1027"],
    sample_hash="51bd8ee44a01a0fcc7235052fddecaa84f8c94f5dbd0343145401a78614c135b",
)
