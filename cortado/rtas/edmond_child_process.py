# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="58041706-c636-4043-b221-3d59f977b7e2",
    platforms=["macos"],
    endpoint_rules=[{"rule_name": "Potential Persistence via Emond", "rule_id": "1cd247d8-00e8-4c62-b9ee-90cd1811460b"}],
    siem_rules=[{"rule_name": "Suspicious Emond Child Process", "rule_id": "3e3d15c6-1509-479a-b125-21718372157e"}],
    techniques=["T1546"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/emond"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching bash from fake emond command")
    _common.execute([masquerade], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
