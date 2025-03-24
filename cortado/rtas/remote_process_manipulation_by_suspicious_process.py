# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="cfe1d663-20b3-4a1b-a98e-9ce83d5e9f7c",
    name="remote_process_manipulation_by_suspicious_process",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="902f471c-27b4-4e78-b344-be46c6cfb72b", name="Remote Process Manipulation by Suspicious Process")
    ],
    techniques=['T1055'],
    sample_hash="4628d075894ec8212dfe33f263873efc3cfb012889015810eb60453a0a1e8889",
)
