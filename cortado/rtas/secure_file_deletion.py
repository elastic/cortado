# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import subprocess
import tempfile
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9cb42759-a161-4d93-b07d-3c8254dc8838",
    name="secure_file_deletion",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="55d551c6-333b-4665-ab7e-5d14a59715ce", name="PsExec Network Connection")],
    techniques=["T1569"],
)
def main():
    temp_path = Path(tempfile.gettempdir()) / "test-name"
    sdelete_path = _common.get_resource_path("bin/sdelete.exe")

    with _common.file_with_data(temp_path, "A"):
        _ = subprocess.check_call([sdelete_path, "/accepteula", temp_path])
