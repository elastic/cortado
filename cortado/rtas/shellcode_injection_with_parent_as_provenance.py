
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="d32778b8-f454-4552-8505-f7b52df6ae00",
    name="shellcode_injection_with_parent_as_provenance",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="631df705-0636-4f83-8374-24d61307735e", name="Shellcode Injection with Parent as Provenance")
    ],
    techniques=['T1055'],
    sample_hash="2fe6a7ae63c878bd84d7b829349b309e7c84194ddbb6a779816f5b84cd8ad45d",
)
