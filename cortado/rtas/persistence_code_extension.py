# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="4ef86185-1a6e-4dd4-915c-d0f4281f68aa",
    platforms=["macos"],
    endpoint_rules=[{
        'rule_id': '1f207515-b56f-4d15-929e-b6c0b1bb34f2',
        'rule_name': 'Suspicious Manual VScode Extension Installation'
    }],
    siem_rules=[],
    techniques=[""],
)


@_common.requires_os(*metadata.platforms)
def main():

    _common.log("Executing code commands to load fake extension.")
    _common.execute(["code", "--install-extension", "test"])


if __name__ == "__main__":
    exit(main())
