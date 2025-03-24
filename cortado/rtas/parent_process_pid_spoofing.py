
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="6f58920e-11e4-44d1-8883-699e02841a37",
    name="parent_process_pid_spoofing",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="816ba7e7-519a-4f85-be2a-bacd6ccde57f", name="Parent Process PID Spoofing")
    ],
    techniques=['T1134', 'T1134.004'],
    sample_hash="80e5cb11ae2512da3b7be501b469d6fc1a69a2017a143b9897023da9e366325f",
)
