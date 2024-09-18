# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e45cd941-dee1-4275-8c63-2f8cab2cf8a6",
    name="privilege_escalation_tcc_bypass",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="8446b30d-a9c4-4646-8261-979c06edd0ff",
            name="Potential Privilege Escalation via TCC bypass with fake TCC.db",
        )
    ],
    siem_rules=[],
    techniques=["T1068"],
)
def main():
    log.info("Executing deletion on /tmp/TCC.db file.")
    _common.create_file_with_data("/tmp/TCC.db", "testing")
