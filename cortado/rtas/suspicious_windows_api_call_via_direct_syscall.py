# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="23606530-6eda-4a3d-b4b5-9796ec767619",
    name="suspicious_windows_api_call_via_direct_syscall",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="fe44381a-435c-4e19-ad89-40ac3750f514", name="Suspicious Windows API Call via Direct Syscall")
    ],
    techniques=['T1055'],
    sample_hash="23f6f5fcea5cb6e919ab5480bccd06d1c863a1f688124d4ee8e27349cc86ae69",
)
