# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="900e8599-1d5f-4522-9aed-6eab82de2bad",
    platforms=["linux"],
    endpoint_rules=[
        {
            "rule_name": "Kernel Module Removal",
            "rule_id": "e80ba5e4-b6c6-4534-87b0-8c0f4e1d97e7",
        }
    ],
    siem_rules=[
        {
            "rule_name": "Kernel Module Removal",
            "rule_id": "cd66a5af-e34b-4bb0-8931-57d0a043f2ef"
        }
    ],
    techniques=["T1562", "T1562.001", "T1547", "T1547.006"],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/rmmod"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Launching fake commands to remove Kernel Module")
    _common.execute([masquerade], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
