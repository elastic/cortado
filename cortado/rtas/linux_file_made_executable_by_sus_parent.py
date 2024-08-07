# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="97993aa0-7b15-442b-a180-7c158b3339c1",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {
            "rule_name": "Linux File Made Executable by Suspicious Parent",
            "rule_id": "742037b3-3ef6-4a33-84ed-b26fc6ae322c",
        }
    ],
    techniques=["T1222", "T1564"],
)
def main():
    masquerade = "/tmp/chmod"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "+x", "/dev/shm/foo"]

    # Execute command
    _common.log("Launching fake command to simulate chmod")
    _common.execute([*commands], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
