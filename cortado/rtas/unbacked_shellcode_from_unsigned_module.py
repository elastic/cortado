
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="7fbf5e71-138e-474f-a98c-17e9508436d8",
    name="unbacked_shellcode_from_unsigned_module",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="99d3049e-f4af-46a7-9406-33482955bec9", name="Unbacked Shellcode from Unsigned Module")
    ],
    techniques=['T1055'],
    sample_hash="206559b47dfa7ffc7a40724ddc89cc75c7a068b60cd7d87319157d29438cc5b0",
)
