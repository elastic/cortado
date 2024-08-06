# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata

from pathlib import Path

metadata = RtaMetadata(
    id="8bd875f2-eafb-4151-bfb7-4bd97192400d",
    platforms=["macos"],
    endpoint_rules=[{
        'rule_id': '3da48cdd-262a-42a9-af2f-c82ef639b9e3',
        'rule_name': 'Persistence via a Masqueraded Plist Filename'
    }],
    siem_rules=[],
    techniques=[""],
)


@_common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/bash"
    masquerade2 = "/tmp/testmodify"

    tmp_file = f"{Path.home()}/Library/LaunchAgents/com.apple.test.plist"

    # create tmp file
    if not Path(tmp_file).exists():
        Path(tmp_file).write_text("test")

    # create masquerades
    _common.copy_file("/bin/bash", masquerade)
    _common.create_macos_masquerade(masquerade2)

    # remove signature
    _common.execute(["codesign", "--remove-signature", masquerade], timeout=5, kill=True)

    # Execute commands
    _common.log("Launching fake commands to modify com.apple.test.plist")
    command = f"{masquerade} -c echo '1' >> {tmp_file}"
    _common.execute([masquerade2, "childprocess", command], shell=True, timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
    _common.remove_file(tmp_file)


if __name__ == "__main__":
    exit(main())
