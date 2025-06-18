# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="f16c1b45-2d5c-499b-a117-2db5794c4ce9",
    name="remote_thread_context_manipulation",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="c456266f-e920-4acb-9b32-711fa7b94ca5", name="Remote Thread Context Manipulation")
    ],
    techniques=['T1055'],
    sample_hash="bdfb4f30c9fb3a9ff5858926086443518095fced463371da099b9ad977d53c83",
)
