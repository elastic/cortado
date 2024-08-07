# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="fcd2d0fe-fed2-424a-bdc5-e9bef5031344",
    platforms=[OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="25ae94f5-0214-4bf1-b534-33d4ffc3d41c", name="Network Activity Detected via cat")],
    siem_rules=[RuleMetadata(id="afd04601-12fc-4149-9b78-9c3f8fe45d39", name="Network Activity Detected via cat")],
    techniques=[""],
)
def main():
    _common.log("Creating a fake cat executable..")
    masquerade = "/tmp/cat"
    source = _common.get_path("bin", "netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)

    _common.log("Granting execute permissions...")
    _common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "netcon", "-h", "127.0.0.1", "-p", "1337"]

    _common.log("Simulating cat network activity..")
    _common.execute([*commands], timeout=5)
    _common.log("Cat network simulation successful!")
    _common.log("Cleaning...")
    _common.remove_file(masquerade)
    _common.log("RTA completed!")


if __name__ == "__main__":
    exit(main())
