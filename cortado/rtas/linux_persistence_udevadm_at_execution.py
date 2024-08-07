# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="2119cf83-795b-4049-a416-bb46a5aad3a0",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {"rule_name": "At Utility Launched through Udevadm", "rule_id": "47e5595e-1920-4fdd-9a1c-cf712e1112d1"}
    ],
    techniques=["T1037"],
)
def main():
    # Path for the fake udevadm script
    fake_udevadm = "/tmp/udevadm"

    # Create fake at executable
    masquerade = "/tmp/at"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Create a fake udevadm script that launches at
    with open(fake_udevadm, "w") as script:
        script.write("#!/bin/bash\n")
        script.write("/tmp/at\n")

    # Make the script executable
    _common.execute(["chmod", "+x", fake_udevadm])
    _common.execute(["chmod", "+x", masquerade])

    # Execute the fake udevadm script
    _common.log("Launching a shell that executes a payload as a child of fake udevadm")
    _common.execute([fake_udevadm], timeout=5, kill=True, shell=True)

    # Cleanup
    _common.remove_file(fake_udevadm)
    _common.remove_file(masquerade)


