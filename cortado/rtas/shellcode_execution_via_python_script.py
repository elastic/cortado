# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="9898d2a6-f4d9-45f1-92d5-53bc6fb2015b",
    name="shellcode_execution_via_python_script",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="1d0a1b39-a29e-4370-a712-546ed047f5f5", name="Shellcode Execution via Python Script")
    ],
    techniques=['T1055'],
    sample_hash="d8e3240539b9d124c081506af59cf87d47b89139e423894063ac9389697b49a2",
)
