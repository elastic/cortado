# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


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
    _common.execute([arp, "-a"], timeout=10)
