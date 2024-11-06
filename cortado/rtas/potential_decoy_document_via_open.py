# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="76568652-92c8-4080-a30b-59b4b5438eb8",
    name="potential_decoy_document_via_open",
    platforms=[OSType.MACOS],
    endpoint_rules=[RuleMetadata(id="3f2c51ce-5da8-4c9b-8a39-17677ed08eb9", name="Potential Decoy Document via Open")],
    techniques=["T1204"],
    sample_hash="7769af718266fcc91c9f39eb71d1b137156b95d6e6704d9b783988e3421ac656",
)
