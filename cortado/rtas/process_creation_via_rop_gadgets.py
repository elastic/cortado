# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="1badc49a-e6eb-4d15-9582-60e8ab40b8dc",
    name="process_creation_via_rop_gadgets",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="4cd250a2-82a0-463b-adda-5256cee422ce", name="Process Creation via ROP Gadgets")
    ],
    techniques=['T1055'],
    sample_hash="6c4a8bd310ce4f1146d84ca455a560fd082e7d22d8b8c772cef5ce89f68e3191",
)
