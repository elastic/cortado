# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="9b0bbe6d-2116-4327-930b-51e3e5097487",
    platforms=[OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="3337a10c-e950-4827-a44e-96a688fba221", name="Potential Linux Hack Tool Launched")],
    siem_rules=[RuleMetadata(id="1df1152b-610a-4f48-9d7a-504f6ee5d9da", name="Potential Linux Hack Tool Launched")],
    techniques=[""],
)
def main():
    masquerade = "/tmp/crackmapexec"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Launching fake command to simulate a CME process")
    _common.execute([masquerade], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
