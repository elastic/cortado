# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata

metadata = RtaMetadata(
    id="b2603bac-ba1c-4e6e-a041-ed8772fded75",
    platforms=["linux"],
    endpoint_rules=[{"rule_id": "276a5df0-7e20-4218-ade1-3f3ed711d4cb",
               "rule_name": "Potential Multi Architecture File Downloads"}],
    siem_rules=[],
    techniques=["T1105"]
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/curl"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Launching fake commands to mimic multi arch file downloads")
    command = "http://fake/mipsel"

    for i in range(8):
        _common.execute([masquerade, command], timeout=.3, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
