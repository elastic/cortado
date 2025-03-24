
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="7bc977f9-cbd5-4517-8f12-fb5e86c590fa",
    name="suspicious_wmi_library_load",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="3cd302aa-098b-4da6-bf20-8d37efe5f861", name="Suspicious WMI Library Load")
    ],
    techniques=['T1047'],
    sample_hash="ca418ccff111b4ce22e4d4c67669ecb8fa3e03d6113d6ff21f3e580bbc994c0d",
)
