# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="95e761e4-5161-43b4-b34d-95e846a0c94c",
    name="remote_process_injection_via_python",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="634dcd98-0656-48a8-bd41-5fa025b6c812", name="Remote Process Injection via Python")
    ],
    techniques=['T1055'],
    sample_hash="d8e3240539b9d124c081506af59cf87d47b89139e423894063ac9389697b49a2",
)
