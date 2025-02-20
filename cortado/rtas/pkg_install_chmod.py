# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="caa6feb7-cc17-425f-996f-b1b69efa93e2",
    name="pkg_install_chmod",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="75f5d51a-218f-4d5b-80e5-eb74e498fde4", name="File Made Executable via Pkg Install Script"),
        RuleMetadata(
            id="42ab2c0f-b10d-467d-8c6d-def890cf3f68", name="File Made Executable by Suspicious Parent Process"
        ),
        RuleMetadata(id="f06d9987-33f8-44b7-b815-c1f66fb39d25", name="Suspicious File Create via Pkg Install Script"),
    ],
    techniques=["T1222", "T1222.002", "T1564", "T1546", "T1546.016"],
)
def main():
    dest_file = "/tmp/test.py"
    source_file = "/tmp/test.txt"
    masquerade = "/Users/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    command = f"chmod +x {source_file}"
    log.info("Launching fake bash commands to execute chmod on file via pkg install")
    with _common.file_with_data(source_file, "testing"):
        _ = _common.execute_command(
            [
                masquerade,
                "childprocess",
                command,
                "childprocess",
                f"cp {source_file} {dest_file}",
                "childprocess",
                "/tmp/PKInstallSandbox.*/Scripts/*/postinstall",
            ],
            timeout_secs=10,
        )

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(dest_file)
