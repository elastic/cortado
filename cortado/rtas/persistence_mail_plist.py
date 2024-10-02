# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a9754fdb-2beb-454a-b918-36a56c5bf7bd",
    name="persistence_mail_plist",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="482e5ab2-029c-4896-afc0-f3e6b8280920", name="Suspicious Apple Mail Rule Creation or Modification"
        )
    ],
)
def main():
    log.info("Executing deletion on SyncedRules.plist file.")
    plist = f"{Path.home()}/Library/Mobile Documents/com.apple.mail/Data/test/MailData/SyncedRules.plist"
    output_file = Path(plist)
    output_file.parent.mkdir(exist_ok=True, parents=True)
    _common.create_file_with_data(str(plist), "testing")
    _common.remove_directory(f"{Path.home()}/Library/Mobile Documents/com.apple.mail/Data/test/")
