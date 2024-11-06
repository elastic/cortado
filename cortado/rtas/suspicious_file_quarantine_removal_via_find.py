# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="180d0e8f-1e8e-4d10-b0fe-646a136e35b5",
    name="suspicious_file_quarantine_removal_via_find",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="c43102bc-f307-48a4-bfc5-a02444b3fed2", name="Suspicious file quarantine removal via Find")
    ],
    techniques=["T1204"],
    sample_hash="fa174666d2bd37f8f97e052153c1b2e3276ce47975afbd1a811dbb6979b73920",
)
