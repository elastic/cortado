# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="08717def-f6f4-4ff9-8091-4f13411c308d",
    name="potential_shellcode_injection_via_clr",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="1370f164-1809-4668-ad6c-dbf5bd278120", name="Potential Shellcode Injection via CLR")
    ],
    techniques=['T1055'],
    sample_hash="0478f76edf55a95129c2dc410864c96e662827e14cda5d63f31456bb66122e42",
)
