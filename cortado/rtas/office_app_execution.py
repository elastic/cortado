# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1a483c55-443d-4d01-a9de-e2c69df744f3",
    name="office_app_execution",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="64021ef9-19d3-4797-ac3c-79e38d5e5a5a",
            name="Initial Access or Execution via Microsoft Office Application",
        )
    ],
    techniques=["T1105", "T1140", "T1027", "T1566", "T1547", "T1204", "T1059"],
)
def main():
    masquerade = "/tmp/Microsoft PowerPoint"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake Microsoft Office process")
    _ = _common.execute_command(masquerade, shell=True, timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
