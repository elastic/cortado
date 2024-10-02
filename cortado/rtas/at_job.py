# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="084c5d8f-2578-4fe0-bc6f-f6c44205804a",
    name="at_job",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="779f18ce-1457-457c-80e1-3a5d146c2dc0", name="At Job Creation or Modification by an Unusual Process"
        )
    ],
    techniques=["T1053", "T1053.002"],
)
def main():
    log.info("Executing file creation on /private/var/at/jobs/test.")
    _common.create_file_with_data("/private/var/at/jobs/test", "testing")
