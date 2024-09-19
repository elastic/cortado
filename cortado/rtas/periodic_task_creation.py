# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="31161e21-c290-4e51-a6d3-2865710793ff",
    name="periodic_task_creation",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="48ec9452-e1fd-4513-a376-10a1a26d2c83", name="Potential Persistence via Periodic Tasks")
    ],
    techniques=["T1053"],
)
def main():
    log.info("Executing file modification on periodic file test.conf to mimic periodic tasks creation")
    _common.create_file_with_data("/private/etc/periodic/test.conf", "testing")
