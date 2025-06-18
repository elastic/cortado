# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="6d1885f8-b82f-48ff-b621-50b507ced8e8",
    name="potential_operation_via_direct_syscall",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="30106950-2383-49cd-b462-ed55be29b10b", name="Potential Operation via Direct Syscall")
    ],
    techniques=['T1055'],
    sample_hash="6c4a8bd310ce4f1146d84ca455a560fd082e7d22d8b8c772cef5ce89f68e3191",
)
