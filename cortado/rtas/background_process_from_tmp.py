# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="fa2bbba7-66f4-4fd6-9c81-599d58fe67e8",
    name="background_process_from_tmp",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="603ac59e-9cca-4c48-9750-e38399079043", name="Background Process Execution via Shell")
    ],
    siem_rules=[],
    techniques=["T1059", "T1059.004"],
)
def main():
    masquerade = "/tmp/sh"
    _common.create_macos_masquerade(masquerade)

    log.info("Executing background processes via sh from tmp directory.")
    command = 'bash -c "/* &"'
    _ = _common.execute_command([masquerade, "childprocess", command], shell=True, timeout_secs=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
