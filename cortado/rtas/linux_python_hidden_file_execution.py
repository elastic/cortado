# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata

metadata = RtaMetadata(
    id="d2c9baa4-6dda-46ff-acaa-f70ac0d3391b",
    platforms=["linux"],
    endpoint_rules=[
        {
            "rule_name": "Linux Hidden Folder or File Execution via Python",
            "rule_id": "b25ec4e7-34f1-40c2-b683-bbf1dcdd84e5"
        }
    ],
    techniques=["T1059"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/python"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "python", "/dev/shm/.foo"]

    # Execute command
    _common.log("Launching fake command to simulate Python hidden execution")
    _common.execute([*commands], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
