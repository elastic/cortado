# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="54be1902-0608-49df-8053-40020d8a9210",
    name="fltmc_unload",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="5b39f347-077c-4a1e-8d3c-6f7789ca09e8",
            name="Potential Defense Evasion via Filter Manager Control Program",
        )
    ],
    siem_rules=[],
    techniques=["T1562"],
)
def main():
    # Execute command
    log.info("Executing ftlmc unload on non-exisiting driver")
    _ = _common.execute_command(["fltmc.exe", "unload", "ElasticNonExisting"], timeout_secs=10)
