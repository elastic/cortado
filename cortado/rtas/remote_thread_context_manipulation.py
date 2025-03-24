
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="72b939a6-34c4-4973-bb95-e8ddcc5e56cc",
    name="remote_thread_context_manipulation",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="c456266f-e920-4acb-9b32-711fa7b94ca5", name="Remote Thread Context Manipulation")
    ],
    techniques=['T1055'],
    sample_hash="bdfb4f30c9fb3a9ff5858926086443518095fced463371da099b9ad977d53c83",
)
