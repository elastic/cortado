# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="062e4b3c-c8fb-4bbc-9688-05e4f596e9be",
    name="linux_suspicious_process_execution_by_zoom",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="84b81b96-58dd-4c0d-9b2e-35023ab5ee88",
            name="Suspicious Process Execution by Zoom on macOS or Linux",
        ),
    ],
    techniques=["T1059", "T1059.004", "T1203"],
)
def main() -> None:
    zoom_dir = Path("/opt/zoom")
    zoom = zoom_dir / "zoom"

    if zoom.exists() or zoom.is_symlink():
        raise RuntimeError(f"Refusing to replace an existing Zoom executable at {zoom}")

    remove_zoom_dir = not zoom_dir.exists()

    try:
        zoom_dir.mkdir(parents=True, exist_ok=True)

        source = _common.get_resource_path("bin/linux_ditto_and_spawn_parent_child")
        _common.copy_file(source, zoom)

        log.info("Launching a shell as a child of the masqueraded Zoom process")
        _ = _common.execute_command([zoom, "childprocess", "/bin/bash"], timeout_secs=5)
    finally:
        _common.remove_file(zoom)
        if remove_zoom_dir:
            _common.remove_directory(zoom_dir)
