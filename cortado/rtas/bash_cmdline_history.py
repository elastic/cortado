# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata

metadata = RtaMetadata(
    id="631a211d-bdaa-4b9d-a786-31d84d7bc070",
    platforms=["linux"],
    endpoint_rules=[{"rule_id": "31da6564-b3d3-4fc8-9a96-75ad0b364363",
               "rule_name": "Tampering of Bash Command-Line History"}],
    siem_rules=[],
    techniques=["T1070", "T1070.003"]
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/history"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Launching fake builtin commands for tampering of bash command line history")
    command = "-c"
    _common.execute([masquerade, command], timeout=10, kill=True, shell=True)
    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
