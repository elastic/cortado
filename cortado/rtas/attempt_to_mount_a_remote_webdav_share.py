
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="4422442a-e580-4f65-99ca-c1fc37141fcf",
    name="attempt_to_mount_a_remote_webdav_share",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="0a364281-5edc-4f75-a839-48b150cec3f2", name="Attempt to Mount a Remote WebDav Share")
    ],
    techniques=['T1204', 'T1204.002', 'T1021', 'T1021.002'],
    sample_hash="eb1429e87b46440f38ff2347368bb60ae8fe5904b8e7174084c42c2daf978a53",
)
