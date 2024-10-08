# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c5ae5daf-50f4-4cbb-84ed-d0ee7750bad0",
    name="linux_decoded_or_decrypted_payload_written_to_sus_dir",
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
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "-out", "enc", "-d", "/dev/shm/foo"]

    # Execute command
    log.info("Launching fake command to simulate OpenSSL encoding")
    _ = _common.execute_command(commands, timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
