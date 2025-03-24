# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="8058bc1b-83c5-4990-83f7-2bfcde5c3aa4",
    name="suspicious_execution_via_windows_services",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="84595d39-df78-49d6-a999-48792482b255", name="Suspicious Execution via Windows Services")
    ],
    techniques=['T1543', 'T1543.003'],
    sample_hash="79dc900d0bfac9749b5ddb5d237b3d384769104ad22eeec29a30752263593f67",
)
