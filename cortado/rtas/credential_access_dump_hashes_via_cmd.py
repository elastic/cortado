# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="0a6fcfaa-db5e-498f-9253-0f76b8a18687",
    platforms=["macos"],
    endpoint_rules=[
        {"rule_name": "Dumping Account Hashes via Built-In Commands", "rule_id": "2ed766db-e0b0-4a07-8ec1-4e41dd406b64"}
    ],
    siem_rules=[
        {"rule_name": "Dumping Account Hashes via Built-In Commands", "rule_id": "02ea4563-ec10-4974-b7de-12e65aa4f9b3"}
    ],
    techniques=["T1003"],
)


@_common.requires_os(*metadata.platforms)
def main():

    _common.log("Executing defaults commands to dump hashes.")
    _common.execute(["defaults", "ShadowHashData", "-dump"])


if __name__ == "__main__":
    exit(main())
