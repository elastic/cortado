# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Encrypting files with 7zip
# RTA: sevenzip_encrypted.py
# ATT&CK: T1022
# Description: Uses "bin\.exe" to perform encryption of archives and archive headers.

import base64
import sys
from pathlib import Path

from . import RtaMetadata, _common

metadata = RtaMetadata(
    id="6cd35061-278b-45e7-a9cb-86b48bc47884",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{"rule_id": "45d273fb-1dca-457d-9855-bcb302180c21", "rule_name": "Encrypting Files with WinRar or 7z"}],
    techniques=["T1560"],
)


SEVENZIP = _common.get_path("bin", "7za.exe")


def create_exfil(path=Path("secret_stuff.txt").resolve()):
    _common.log("Writing dummy exfil to %s" % path)
    with open(path, "wb") as f:
        f.write(base64.b64encode(b"This is really secret stuff\n" * 100))
    return path


@_common.requires_os(*metadata.platforms)
@_common.dependencies(SEVENZIP)
def main(password="s0l33t"):
    # create 7z.exe with not-7zip name, and exfil
    svnz2 = Path("a.exe").resolve()
    _common.copy_file(SEVENZIP, svnz2)
    exfil = create_exfil()

    exts = ["7z", "zip", "gzip", "tar", "bz2", "bzip2", "xz"]
    out_jpg = Path("out.jpg").resolve()

    for ext in exts:
        # Write archive for each type
        out_file = Path("out." + ext).resolve()
        _common.execute([svnz2, "a", out_file, "-p" + password, exfil], mute=True)
        _common.remove_file(out_file)

        # Write archive for each type with -t flag
        if ext == "bz2":
            continue

        _common.execute([svnz2, "a", out_jpg, "-p" + password, "-t" + ext, exfil], mute=True)
        _common.remove_file(out_jpg)

    _common.execute([SEVENZIP, "a", out_jpg, "-p" + password, exfil], mute=True)
    _common.remove_files(exfil, svnz2, out_jpg)


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
