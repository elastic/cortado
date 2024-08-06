# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata

metadata = RtaMetadata(
    id="4076de6c-6caa-40b3-bfb6-548645823376",
    platforms=["linux"],
    endpoint_rules=[
        {
            "rule_name": "Init.d Script Executed Binary from Unusual Location",
            "rule_id": "879c083c-e2d9-4f75-84f2-0f1471d915a8"
        }
    ],
    techniques=["T1037"],
)


@_common.requires_os(*metadata.platforms)
def main():

    # Path for the fake initd script
    fake_initd = "/etc/init.d/rta"

    # Create fake sh executable
    masquerade = "/tmp/sh"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake initd script that launches sh
    with open(fake_initd, 'w') as script:
        script.write('#!/bin/bash\n')
        script.write('/tmp/sh\n')

    # Make the script executable
    _common.execute(['chmod', '+x', fake_initd])
    _common.execute(['chmod', '+x', masquerade])

    # Execute the fake initd script
    _common.log("Launching a shell that executes a payload as a child of fake initd")
    _common.execute([fake_initd], timeout=5, kill=True, shell=True)

    # Cleanup
    _common.remove_file(fake_initd)


if __name__ == "__main__":
    exit(main())
