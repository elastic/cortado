
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="e23063b3-b4e6-402e-a0d1-150979d75dff",
    name="firewall_policy_changed_by_a_suspicious_process",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="bf072c39-90bc-4b1b-9c78-1d8a9bd6f0e1", name="Firewall Policy Changed by a Suspicious Process")
    ],
    techniques=['T1562', 'T1562.001'],
    sample_hash="bdf06c7902c1d0b705be7415aad80836686d4d44482ced0bb2d4c7670c501255",
)
