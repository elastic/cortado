# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="dbbfda7f-376d-482d-b7ea-3bb1e8918584",
    name="file_mod_via_chmod",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="42ab2c0f-b10d-467d-8c6d-def890cf3f68", name="File Made Executable by Suspicious Parent Process"
        )
    ],
    siem_rules=[],
    techniques=["T1222", "T1222.002", "T1564"],
)
def main():
    log.info("Executing chmod on tmp files.")
    with _common.file_with_data("/tmp/test.txt", "testing"):
        _ = _common.execute_command(["chmod", "+x", "/tmp/test.txt"])
