# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="0a6fcfaa-db5e-498f-9253-0f76b8a18687",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="2ed766db-e0b0-4a07-8ec1-4e41dd406b64", name="Dumping Account Hashes via Built-In Commands")
    ],
    siem_rules=[
        RuleMetadata(id="02ea4563-ec10-4974-b7de-12e65aa4f9b3", name="Dumping Account Hashes via Built-In Commands")
    ],
    techniques=["T1003"],
)
def main():
    _common.log("Executing defaults commands to dump hashes.")
    _common.execute(["defaults", "ShadowHashData", "-dump"])


if __name__ == "__main__":
    exit(main())
