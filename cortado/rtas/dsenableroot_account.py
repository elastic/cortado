# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="eddbcd95-2922-46e4-b356-86d3bc8aeadc",
    platforms=["macos"],
    endpoint_rules=[],
    siem_rules=[{'rule_id': 'cc2fd2d0-ba3a-4939-b87f-2901764ed036', 'rule_name': 'Attempt to Enable the Root Account'}],
    techniques=[""],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/dsenableroot"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake dsenableroot commands to mimic enabling root accounts.")
    _common.execute([masquerade], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
