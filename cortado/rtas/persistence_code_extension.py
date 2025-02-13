# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4ef86185-1a6e-4dd4-915c-d0f4281f68aa",
    name="persistence_code_extension",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="1f207515-b56f-4d15-929e-b6c0b1bb34f2", name="Suspicious Manual VScode Extension Installation")
    ],
)
def main():
    log.info("Executing code commands to load fake extension.")
    _ = _common.execute_command(["code", "--install-extension", "test"])
