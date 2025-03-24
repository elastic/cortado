
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="97e97ffa-7209-4086-adba-add9f3c9548d",
    name="suspicious_directshow_devices_enumeration",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="d6699c83-fb2f-4029-8fb4-0f628f131a22", name="Suspicious DirectShow Devices Enumeration")
    ],
    techniques=['T1123', 'T1125', 'T1112'],
    sample_hash="518d9aeaf075a297467fbd6962f4a04f7f256680f9b506b4e4b51b67c185b365",
)
