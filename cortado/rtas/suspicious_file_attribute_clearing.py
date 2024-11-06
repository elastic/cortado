# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="57857894-019c-4752-be86-4a6c4910ce25",
    name="suspicious_file_attribute_clearing",
    platforms=[OSType.MACOS],
    endpoint_rules=[RuleMetadata(id="e12fa85d-e173-402f-b43e-5bbc6210cdd5", name="Suspicious file attribute Clearing")],
    techniques=["T1553"],
    sample_hash="d3b3a3439a8dff9050d6e461323776be0ae004e8d39dc93eb016626cfc62204a",
)
