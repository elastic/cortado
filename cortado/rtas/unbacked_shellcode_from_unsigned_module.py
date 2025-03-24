# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="c9dc4331-5ef7-4d7b-a109-7364600c1947",
    name="unbacked_shellcode_from_unsigned_module",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="99d3049e-f4af-46a7-9406-33482955bec9", name="Unbacked Shellcode from Unsigned Module")
    ],
    techniques=['T1055'],
    sample_hash="903e9205b7c364adb9fe13f85d0029b02cc306bf815275ed4988238654447734",
)
