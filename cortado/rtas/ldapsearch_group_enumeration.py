# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="370c3432-65f5-4068-b879-916bc1297c60",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_name": "Enumeration of Users or Groups via Built-in Commands",
            "rule_id": "6e9b351e-a531-4bdc-b73e-7034d6eed7ff",
        }
    ],
    techniques=["T1069", "T1087"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/ldapsearch"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake ldapsearch commands to mimic user or group enumeration")
    _common.execute([masquerade, "testing"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
