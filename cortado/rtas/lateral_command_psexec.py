# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: PsExec Lateral Movement
# RTA: lateral_command_psexec.py
# ATT&CK: T1035, T1077
# Description: Runs PSExec to move laterally

import sys

from . import _common


@register_code_rta(
    id="90cf6001-11a7-410b-b259-cf20a029b929",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="55d551c6-333b-4665-ab7e-5d14a59715ce", name="PsExec Network Connection")],
    techniques=["T1569"],
)
@_common.dependencies(_common.PS_EXEC)
def main(remote_host=None):
    remote_host = remote_host or _common.get_ip()
    _common.log("Performing PsExec to %s" % remote_host)
    _common.execute([_common.PS_EXEC, "\\\\%s" % remote_host, "-accepteula", "ipconfig"])


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
