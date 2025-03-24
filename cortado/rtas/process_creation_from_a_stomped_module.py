# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="09e70b8f-cfa0-4277-b9db-23381a2cf1ee",
    name="process_creation_from_a_stomped_module",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="b444173e-ef79-4e76-b329-f0926aa249ee", name="Process Creation from a Stomped Module")
    ],
    techniques=['T1055'],
    sample_hash="633c016f6f7f3eab1995d7fe36f60721a042fd78496cc43516cc3a2047ab0fcf",
)
