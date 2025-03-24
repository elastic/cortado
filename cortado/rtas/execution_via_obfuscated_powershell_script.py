
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="cf6a6563-fcfb-4c99-a4d9-0c6216ba5878",
    name="execution_via_obfuscated_powershell_script",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="ce95fc52-051e-4409-9c99-f2daf3e6e609", name="Execution via Obfuscated PowerShell Script")
    ],
    techniques=['T1059', 'T1059.001'],
    sample_hash="47ae6d232dee297bf10ee6b88ee560801c3e7b0504485e254e4bc69b611ba3d8",
)
