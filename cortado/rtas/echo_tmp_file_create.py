# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="2182f7e5-fc4b-4476-86c3-e7128dfcaa7a",
    name="echo_tmp_file_create",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="cd3a06dc-58c3-4d57-a03a-0d8991f237e7", name="Suspicious File Overwrite and Modification via Echo"
        )
    ],
    siem_rules=[],
    techniques=["T1027", "T1059", "T1059.004"],
)
def main():
    file_path = "/tmp/test"
    masquerade = "/tmp/testbin"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake bash commands to abnormal echo shell commands")
    command = f"bash -c 'echo* > {file_path}'"
    _ = _common.execute_command([masquerade, "childprocess", command], timeout_secs=10, kill=True, shell=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(file_path)
