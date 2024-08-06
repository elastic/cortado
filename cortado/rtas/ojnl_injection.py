# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata

metadata = RtaMetadata(
    id="b48a9dd2-8fe7-41e1-9af2-65f609a54237",
    platforms=["linux"],
    endpoint_rules=[{"rule_id": "8fff17c6-f0ba-4996-bcc3-342a9ebd0ef3",
               "rule_name": "Remote Code Execution via Confluence OGNL Injection"}],
    siem_rules=[],
    techniques=["T1190"]
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/confluence/jre/fake/java"
    masquerade2 = "/tmp/bash"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = _common.get_path("bin", "linux_ditto_and_spawn_parent_child")
    _common.copy_file(source, masquerade)
    _common.copy_file(source, masquerade2)

    # Execute command
    _common.log("Launching fake commands for Remote Code Execution via Confluence")
    command = f"{masquerade2} date"
    _common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
