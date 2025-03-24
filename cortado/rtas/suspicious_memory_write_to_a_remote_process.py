
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="5c313b82-cf77-4641-9b0e-bd36f5e02020",
    name="suspicious_memory_write_to_a_remote_process",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="33270c59-e034-4e5b-accb-b6a23681a0d3", name="Suspicious Memory Write to a Remote Process")
    ],
    techniques=['T1055'],
    sample_hash="84499164a4848a100a22361f38d36ddaea66d01d2e68580271692f9a6fc2a570",
)
