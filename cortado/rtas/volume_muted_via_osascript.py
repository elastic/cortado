# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="c304baa6-b360-422b-bf23-fa71c9303bec",
    name="volume_muted_via_osascript",
    platforms=[OSType.MACOS],
    endpoint_rules=[RuleMetadata(id="6948957d-2988-47a7-b7d8-2dec8bfe172b", name="Volume muted via Osascript")],
    techniques=["T1059"],
    sample_hash="9b839e9169babff1d14468d9f8497c165931dc65d5ff1f4b547925ff924c43fe",
)
