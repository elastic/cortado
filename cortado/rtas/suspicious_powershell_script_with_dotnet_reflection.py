# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="53530324-7735-4702-886b-e056d0c1c118",
    name="suspicious_powershell_script_with_dotnet_reflection",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="dc6caf51-828c-4264-a96f-bcf21ed18762", name="Suspicious PowerShell Script with .NET Reflection")
    ],
    techniques=['T1059', 'T1059.001', 'T1620'],
    sample_hash="370e0cedd9a4f6ab338cfff223f9afce18e1e3b7555558ecfad469279d76573e",
)
