# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata

metadata = RtaMetadata(
    id="ac51c9f0-d8ea-4ee1-9371-f368aab884e9",
    platforms=["linux"],
    endpoint_rules=[
        {
            "rule_name": "Linux Hidden File Mounted",
            "rule_id": "5b544dbb-2c66-42cd-a4ee-8d1e5afe9903"
        }
    ],
    techniques=["T1211", "T1059"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/mount"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "/media/.foo"]

    # Execute command
    _common.log("Launching fake command to simulate hidden file mount")
    _common.execute([*commands], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
