# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="8be64c37-dfc0-4ee4-a4e3-63c42ed33bca",
    name="execution_from_suspicious_stack_trailing_bytes",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="0a26ccb6-41b9-418d-9314-854aadcb1fba", name="Execution from Suspicious Stack Trailing Bytes")
    ],
    techniques=[],
    sample_hash="ad6e942d541570bedea0a2560ecd8ad7783593eef510af7f2f48a8a4d00aa674",
)
