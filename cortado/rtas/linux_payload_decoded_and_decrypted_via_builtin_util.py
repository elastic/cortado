# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="0638a18f-29f9-49a2-b8b5-e0dd21e99412",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {
            "rule_name": "Linux Payload Decoded and Decrypted via Built-In Utilities",
            "rule_id": "bfff8d1b-c4d7-4005-9f49-f494261e5a25",
        }
    ],
    techniques=["T1027", "T1204", "T1059"],
)
def main():
    masquerade = "/tmp/openssl"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "/media/foo", "enc", "-base64", "-d"]

    # Execute command
    _common.log("Launching fake command to simulate file decoding & decryption via OpenSSL")
    _common.execute([*commands], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
