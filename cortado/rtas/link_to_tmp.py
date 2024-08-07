# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="eb5834cf-fcd8-4318-a656-5315a664e61d",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="ccca5e9f-2625-4b95-9b15-d5d8fc56df2c", name="Link Creation to Temp Directory"),
    ],
    siem_rules=[],
    techniques=["T1222", "T1222.002"],
)
def main():
    masquerade = "/tmp/ln"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake ln commands to link to temp directory")
    with _common.temporary_file("testing", "/tmp/test.txt"):
        _common.execute([masquerade, "-s", "/tmp/test.txt"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
