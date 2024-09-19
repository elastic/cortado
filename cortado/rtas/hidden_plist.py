# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="6df524fe-6a1a-417f-8f70-d6140ef739e2",
    name="hidden_plist",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="092b068f-84ac-485d-8a55-7dd9e006715f", name="Creation of Hidden Launch Agent or Daemon")
    ],
    techniques=[""],
)
def main():
    log.info(f"Executing hidden plist creation on {Path.home()}/Library/LaunchAgents/.test.plist")
    _common.temporary_file_helper("testing", file_name=f"{Path.home()}/Library/LaunchAgents/.test.plist")
