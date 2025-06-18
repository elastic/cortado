# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="62e16851-d0e9-464d-91aa-d016cfbfed38",
    name="shellcode_injection_via_powershell",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="98fffa16-53e1-4db9-9126-2d0441cac417", name="Shellcode Injection via PowerShell")
    ],
    techniques=['T1055', 'T1059', 'T1059.001'],
    sample_hash="47ae6d232dee297bf10ee6b88ee560801c3e7b0504485e254e4bc69b611ba3d8",
)
