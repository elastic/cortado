# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="2a391051-b103-450b-be50-fd133b6d05c3",
    name="exec_cmd_arp",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="0635c542-1b96-4335-9b47-126582d2c19a", name="Remote System Discovery Commands")],
    techniques=["T1016", "T1018"],
)
def main():
    arp = "C:\\Windows\\System32\\arp.exe"

    # Execute command
    _ = _common.execute_command([arp, "-a"], timeout_secs=10)
