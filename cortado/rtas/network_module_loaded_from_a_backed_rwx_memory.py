
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="63b2fe46-9685-4ea8-9046-05b57e5143ab",
    name="network_module_loaded_from_a_backed_rwx_memory",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="a1d00ee9-64d6-440a-8940-fd2d940152a6", name="Network Module Loaded from a Backed RWX Memory")
    ],
    techniques=['T1055'],
    sample_hash="adfdb5d77b78750b46681a4792ffa6b30ba6665cad6127d61110ada5a7e139fb",
)
