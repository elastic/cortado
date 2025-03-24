# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="5c536d4c-0e38-47a9-8258-5b6ef4095c7a",
    name="shellcode_execution_via_a_callback_function",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="976d1f98-59ab-452c-858b-cb1596355564", name="Shellcode Execution via a CallBack Function")
    ],
    techniques=['T1055'],
    sample_hash="eeb85ca851a8864c3835c7ae34a29e897524a5de4da362957093ae08549568ec",
)
