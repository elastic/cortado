
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="973e9718-6203-4081-98b3-6e60b3f2c1e8",
    name="suspicious_remote_memory_allocation",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="b2104624-d0e8-4864-8266-605056c6469a", name="Suspicious Remote Memory Allocation")
    ],
    techniques=['T1055'],
    sample_hash="9bba145cc6507236b26e3b1cc0e91e03a4a12299d57573a0679e6c50b7413b06",
)
