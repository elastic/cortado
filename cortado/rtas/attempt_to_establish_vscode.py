# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, _common

metadata = RtaMetadata(
    id="a078ecca-e8b8-4ae8-a76c-3238e74ca34d",
    platforms=["linux"],
    endpoint_rules=[
        RuleMetadata(id="13fd98ce-f1c3-423f-9441-45c50eb462c0", name="Attempt to etablish VScode Remote Tunnel"),
    ],
    siem_rules=[],
    techniques=["T1102", "T1059"],
)


@_common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "/tmp/code"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Executing Fake commands to test Attempt to etablish VScode Remote Tunnel")
    _common.execute([masquerade, "tunnel"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
