# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4d9af153-a878-4ae3-b6c4-b3f14e516f25",
    name="persistence_chrome_extension",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="e8d52cc6-8785-43d2-8e98-30f07e19e16c", name="Manual Loading of a Suspicious Chromium Extension"
        )
    ],
    techniques=["T1176"],
)
def main():
    log.info("Executing chrome commands to load suspicious ext.")
    chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    _ = _common.execute_command([chrome, "--load-extension=/test"])
