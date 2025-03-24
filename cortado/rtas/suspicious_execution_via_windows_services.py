
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import OSType, RuleMetadata, register_hash_rta

register_hash_rta(
    id="b1179737-3bcd-48c3-a070-d52c483c29ce",
    name="suspicious_execution_via_windows_services",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="84595d39-df78-49d6-a999-48792482b255", name="Suspicious Execution via Windows Services")
    ],
    techniques=['T1543', 'T1543.003'],
    sample_hash="adfdb5d77b78750b46681a4792ffa6b30ba6665cad6127d61110ada5a7e139fb",
)
