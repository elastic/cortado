# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="b03b9e9b-28f9-43db-92f8-d50677da1eb9",
    name="suspicious_api_call_from_a_powershell_script",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="6ad0c702-ddf0-4631-ac43-37eeea444ee6", name="Suspicious API Call from a PowerShell Script")
    ],
    techniques=['T1059', 'T1059.001'],
    sample_hash="da4c2a0697dac3f01667714903224d07e21777e57002f1a37c508ec1f489f80d",
)
