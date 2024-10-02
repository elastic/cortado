# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b023cf4b-2856-4170-9ea0-884041904159",
    name="defensive_evasion_reflective_loading",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="16fba7a9-f8f6-43ce-ae24-6a392a48e49c", name="MacOS Monterey Reflective Code Loading")
    ],
    techniques=["T1620", "T1106"],
)
def main():
    log.info("Executing deletion on /private/tmp/NSCreateObjectFileImageFromMemory-test file.")
    _common.create_file_with_data("/private/tmp/NSCreateObjectFileImageFromMemory-test", "testing")
