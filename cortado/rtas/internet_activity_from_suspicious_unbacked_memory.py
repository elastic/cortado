# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="e55a01e6-5a5c-4934-91aa-7dad9e93c59c",
    name="internet_activity_from_suspicious_unbacked_memory",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="7dca0e22-0e3f-4ed0-ad28-eff5617adf75", name="Internet Activity from Suspicious Unbacked Memory")
    ],
    techniques=['T1055'],
    sample_hash="17bc5b41b35d894b37224e5daa66e2c7326e10a8309e299af122c6602afc953e",
)
