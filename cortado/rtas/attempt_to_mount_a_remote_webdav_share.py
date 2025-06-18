# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="0eeb9564-8765-4c29-a2f5-f7670e1cd669",
    name="attempt_to_mount_a_remote_webdav_share",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="0a364281-5edc-4f75-a839-48b150cec3f2", name="Attempt to Mount a Remote WebDav Share")
    ],
    techniques=['T1204', 'T1204.002', 'T1021', 'T1021.002'],
    sample_hash="bbf1699eeb08269b7d7a3982be6fa207f3d767ba9e48c406db102a552db716eb",
)
