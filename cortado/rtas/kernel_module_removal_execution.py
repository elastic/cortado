# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="900e8599-1d5f-4522-9aed-6eab82de2bad",
    name="kernel_module_removal_execution",
    platforms=[OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="e80ba5e4-b6c6-4534-87b0-8c0f4e1d97e7", name="Kernel Module Removal")],
    siem_rules=[RuleMetadata(id="cd66a5af-e34b-4bb0-8931-57d0a043f2ef", name="Kernel Module Removal")],
    techniques=["T1562", "T1562.001", "T1547", "T1547.006"],
)
def main():
    masquerade = "/tmp/rmmod"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching fake commands to remove Kernel Module")
    _ = _common.execute_command(masquerade, shell=True, timeout_secs=10)

    # cleanup
    _common.remove_file(masquerade)
