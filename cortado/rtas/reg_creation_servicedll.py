# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="58b3052d-4242-4b41-9f28-b04ce5962761",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="2c624716-75a1-42d9-bcb8-1defcb9bded9", name="Suspicious Windows Service DLL Creation")
    ],
    siem_rules=[],
    techniques=["T1543"],
)
def main():
    _common.log("Temporarily creating a Service DLL reg key...")

    key = "Software"
    value = "ServiceDLL"
    data = "ServiceDLL"

    with _common.temporary_reg(_common.HKCU, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
