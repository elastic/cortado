# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="76050b81-a8da-43d2-8a83-f18b31162b94",
    name="exec_susp_explorer",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f8ec5b76-53cf-4989-b451-7d16abec7298", name="Suspicious Windows Explorer Execution")
    ],
    techniques=["T1055", "T1036"],
)
def main():
    explorer = "C:\\Windows\\explorer.exe"
    _ = _common.execute_command([explorer, "easyminerRTA"], timeout_secs=1)
