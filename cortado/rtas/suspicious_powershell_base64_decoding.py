# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="fd562890-7835-4621-a768-5f9b2d6e1fbf",
    name="suspicious_powershell_base64_decoding",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="08fa5da1-81af-413d-a960-f7e489c75cfb", name="Suspicious PowerShell Base64 Decoding")
    ],
    techniques=['T1059', 'T1059.001'],
    sample_hash="3b17ec4b7c935487cbfea83e9361dafc0605dde1bca7c8acb9532320d871d345",
)
