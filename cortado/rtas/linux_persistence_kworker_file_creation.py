# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import _common, register_code_rta, OSType, RuleMetadata

@register_code_rta(
    id="5282c9a4-4ce9-48b8-863a-ff453143635a",
    name="linux_persistence_kworker_file_creation",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="ae343298-97bc-47bc-9ea2-5f2ad831c16e", name="Suspicious File Creation via kworker")],
    techniques=["T1547", "T1014"],
)
def main() -> None:
    masquerade = "/tmp/kworker"
    source = _common.get_path("bin", "create_file.elf")
    _common.copy_file(source, masquerade)

    _common.log("Granting execute permissions...")
    _common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "/tmp/evil"]

    _common.log("Simulating file creation activity..")
    _common.execute([*commands], timeout=5)
    _common.log("File creation simulation successful!")
    _common.log("Cleaning...")
    _common.remove_file(masquerade)
    _common.log("RTA completed!")


if __name__ == "__main__":
    sys.exit(main())
