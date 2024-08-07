# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="2f17286a-e4a8-41de-b3fa-595a4be6fb19",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        {
            "rule_name": "Potential Access to Kerberos Cached Credentials",
            "rule_id": "dc8fa849-efb4-45d1-be1a-9472325ff746",
        }
    ],
    siem_rules=[RuleMetadata(id="ad88231f-e2ab-491c-8fc6-64746da26cfe", name="Kerberos Cached Credentials Dumping")],
    techniques=["T1558", "T1003"],
)
def main():
    masquerade = "/tmp/kcc"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake kcc command to load Kerberos tickets")
    _common.execute([masquerade, "copy_cred_cache"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
