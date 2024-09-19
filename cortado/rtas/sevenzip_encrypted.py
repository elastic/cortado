# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Encrypting files with 7zip
# RTA: sevenzip_encrypted.py
# ATT&CK: T1022
# Description: Uses "bin\.exe" to perform encryption of archives and archive headers.

import base64
import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

SEVENZIP_EXE = "bin/7za.exe"


def create_exfil() -> Path:
    path = Path("secret_stuff.txt").resolve()
    log.info("Writing dummy exfil to %s" % path)
    data = base64.b64encode(b"This is really secret stuff\n" * 100)
    _ = path.write_bytes(data)
    return path


@register_code_rta(
    id="6cd35061-278b-45e7-a9cb-86b48bc47884",
    name="sevenzip_encrypted",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="45d273fb-1dca-457d-9855-bcb302180c21", name="Encrypting Files with WinRar or 7z")],
    techniques=["T1560"],
    ancillary_files=[SEVENZIP_EXE],
)
def main():
    password = "s0l33t"

    # create 7z.exe with not-7zip name, and exfil
    svnz2 = Path("a.exe").resolve()
    sevenzip_exe_path = _common.get_resource_path(SEVENZIP_EXE)
    _common.copy_file(sevenzip_exe_path, svnz2)
    exfil = create_exfil()

    exts = ["7z", "zip", "gzip", "tar", "bz2", "bzip2", "xz"]
    out_jpg = Path("out.jpg").resolve()

    for ext in exts:
        # Write archive for each type
        out_file = Path("out." + ext).resolve()
        _ = _common.execute_command([str(svnz2), "a", str(out_file), "-p" + password, str(exfil)])
        _common.remove_file(out_file)

        # Write archive for each type with -t flag
        if ext == "bz2":
            continue

        _ = _common.execute_command([str(svnz2), "a", str(out_jpg), "-p" + password, "-t" + ext, str(exfil)])
        _common.remove_file(out_jpg)

    _ = _common.execute_command([str(sevenzip_exe_path), "a", str(out_jpg), "-p" + password, str(exfil)])
    _common.remove_files([exfil, svnz2, out_jpg])
