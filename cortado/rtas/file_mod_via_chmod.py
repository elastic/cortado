# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="dbbfda7f-376d-482d-b7ea-3bb1e8918584",
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
    _common.log("Executing chmod on tmp files.")
    with _common.temporary_file("testing", "/tmp/test.txt"):
        _common.execute(["chmod", "+x", "/tmp/test.txt"])
