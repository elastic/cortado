# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

# Name: Compression of sensitive files
# RTA: linux_compress_sensitive_files.py
# Description: Uses built-in commands for *nix operating systems to compress known sensitive
#              files, such as etc/shadow and etc/passwd
from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f3ffa89b-de47-4e17-ac8e-385e0e7f8253",
    name="linux_compress_sensitive_files",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="6b84d470-9036-4cc0-a27c-6d90bbfe81ab", name="Sensitive Files Compression")],
    techniques=["T1560", "T1552"],
)
def main():
    log.info("Compressing sensitive files")
    files = ["totally-legit.tar", "official-business.zip", "expense-reports.gz"]

    # we don't want/need these to actually work, since the rule is only looking for command line, so no need for sudo
    commands = [
        ["tar", "-cvf", files[0], "/etc/shadow"],
        ["zip", files[1], "/etc/passwd"],
        ["gzip", "/etc/group", files[2]],
    ]

    for command in commands:
        masquerade = f"/tmp/{command[0]}"
        source = _common.get_resource_path("bin/linux.ditto_and_spawn")
        _common.copy_file(source, masquerade)

        masquerade_command = command
        masquerade_command[0] = masquerade

        try:
            _ = _common.execute_command(masquerade_command, timeout_secs=2)
        except OSError as exc:
            # command doesn't exist on distro - the rule only needs one to trigger
            # also means we will eventually need to explore per distro ground truth when we expand as counts will vary
            log.info(str(exc))

        _common.remove_file(masquerade)
