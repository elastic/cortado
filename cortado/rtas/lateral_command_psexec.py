# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: PsExec Lateral Movement
# RTA: lateral_command_psexec.py
# ATT&CK: T1035, T1077
# Description: Runs PSExec to move laterally


import logging

from . import OSType, RuleMetadata, _common, _const, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="90cf6001-11a7-410b-b259-cf20a029b929",
    name="lateral_command_psexec",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="55d551c6-333b-4665-ab7e-5d14a59715ce", name="PsExec Network Connection")],
    techniques=["T1569"],
    ancillary_files=[_const.PS_EXEC_EXE],
)
def main():
    remote_host = _common.get_host_ip()
    log.info("Performing PsExec to %s" % remote_host)
    ps_exec = _common.get_resource_path(_common.PS_EXEC_EXE)
    _ = _common.execute_command([ps_exec, "\\\\%s" % remote_host, "-accepteula", "ipconfig"])
