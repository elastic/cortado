# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Recursive Password Search
# RTA: findstr_pw_search.py
# ATT&CK: T1081
# Description: Recursively searches files looking for the string "password".

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="332d6bb9-845f-401d-af5a-368f1f10e27a",
    name="findstr_pw_search",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[],
    techniques=[],
)
def main():
    path = "c:\\rta"
    _common.log("Searching for passwords on %s" % path)
    _common.execute(["dir", path, "/s", "/b", "|", "findstr", "password"], shell=True, timeout=15)
