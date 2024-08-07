# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="a960d54a-685b-4058-bb88-a67ff002a280",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {"rule_name": "Linux Powershell Encoded Command", "rule_id": "cd6e64ec-2890-4bd8-9d07-bef06465b06f"}
    ],
    techniques=["T1059"],
)
def main():
    masquerade = "/tmp/pwsh"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    payload += "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    payload += "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    commands = [masquerade, "-EncodedCommand", "-nop", payload]

    # Execute command
    _common.log("Launching fake command to simulate pwsh encoded command execution")
    _common.execute([*commands], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
