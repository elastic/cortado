
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="86b2622b-3fbe-46c7-aa06-40ad07528dda",
    name="shellcode_injection_via_powershell",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="98fffa16-53e1-4db9-9126-2d0441cac417", name="Shellcode Injection via PowerShell")
    ],
    techniques=['T1055', 'T1059', 'T1059.001'],
    sample_hash="72185ca74b611747f0dd76625a3a4dfbd325cac04ffc8840bcb200caa8704908",
)
