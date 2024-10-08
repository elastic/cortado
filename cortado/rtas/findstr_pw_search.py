# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Recursive Password Search
# RTA: findstr_pw_search.py
# ATT&CK: T1081
# Description: Recursively searches files looking for the string "password".

import logging

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="332d6bb9-845f-401d-af5a-368f1f10e27a",
    name="findstr_pw_search",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    techniques=[],
)
def main():
    path = "c:\\rta"
    log.info("Searching for passwords on %s" % path)
    _ = _common.execute_command(["dir", path, "/s", "/b", "|", "findstr", "password"],) timeout_secs=15)
