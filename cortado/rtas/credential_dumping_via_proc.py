# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from . import register_code_rta, OSType, RuleMetadata


@register_code_rta(
    id="e5a98cc9-1f15-4d14-baf2-96bebb932ae9",
    name="credential_dumping_via_proc",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="508226f9-4030-4e86-86cd-63321b7164bc", name="Potential Linux Credential Dumping via Proc Filesystem"
        ),
    ],
    siem_rules=[
        RuleMetadata(
            id="ef100a2e-ecd4-4f72-9d1e-2f779ff3c311", name="Potential Linux Credential Dumping via Proc Filesystem"
        ),
    ],
    techniques=["T1212", "T1003", "T1003.007"],
)
def main() -> None:
    masquerade = "/tmp/ps"
    masquerade2 = "/tmp/strings"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    _common.copy_file(source, masquerade2)

    # Execute command
    _common.log("Launching fake commands to dump credential via proc")
    _common.execute([masquerade, "-eo", "pid", "command"], timeout=5, kill=True)
    _common.execute([masquerade2, "/tmp/test"], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)


if __name__ == "__main__":
    sys.exit(main())
