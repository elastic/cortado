# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="fa2bbba7-66f4-4fd6-9c81-599d58fe67e8",
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

    _common.log("Executing background processes via sh from tmp directory.")
    command = 'bash -c "/* &"'
    _common.execute([masquerade, "childprocess", command], shell=True, timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
