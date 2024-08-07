# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="c5ae5daf-50f4-4cbb-84ed-d0ee7750bad0",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="a0fce633-b6ee-4e4c-b6c7-ba46b8561e9e",
            name="Linux Decoded or Decrypted Payload Written to Suspicious Directory",
        )
    ],
    techniques=["T1027", "T1140", "T1059", "T1204"],
)
def main():
    masquerade = "/tmp/openssl"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "-out", "enc", "-d", "/dev/shm/foo"]

    # Execute command
    _common.log("Launching fake command to simulate OpenSSL encoding")
    _common.execute([*commands], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
