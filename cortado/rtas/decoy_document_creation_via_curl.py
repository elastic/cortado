# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="348e7cbc-d6fa-4f94-97c5-d617cb54ccab",
    name="decoy_document_creation_via_curl",
    platforms=[OSType.MACOS],
    endpoint_rules=[RuleMetadata(id="a39d0c2f-30d0-4a32-b198-41b135f85bad", name="Decoy document creation via Curl")],
    techniques=["T1204"],
    sample_hash="9b839e9169babff1d14468d9f8497c165931dc65d5ff1f4b547925ff924c43fe",
)
