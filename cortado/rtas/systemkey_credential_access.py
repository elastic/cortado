# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d950ef5f-8277-4ed8-a8dd-d2433e791cef",
    name="systemkey_credential_access",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="7d3f98bf-2111-4e5f-9787-9edef8d94dd0", name="Suspicious SystemKey Access via Command Line")
    ],
    siem_rules=[RuleMetadata(id="d75991f2-b989-419d-b797-ac1e54ec2d61", name="SystemKey Access via Command Line")],
    techniques=["T1555"],
)
def main():
    masquerade = "/tmp/bash"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    log.info("Launching fake commands to aquire keychain credentials")
    _ = _common.execute_command([masquerade, "/private/var/db/SystemKey"], timeout_secs=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
