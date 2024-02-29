"""
Archives files into ~/.integrity

Run again to monitor changes.

Copyright (c) 2024 UFSIT Blue Team.
"""

import hashlib
import pathlib
import re
import shutil
import sys
import tempfile

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("USAGE: " + argv[0] + " <FILE_TO_MONITOR>")
        print("Archives files to ~/.integrity")
        print("Run again to monitor for changes")
        print("It is recommended to use absolute paths.")
        return 0

    base_directory = pathlib.Path.home() / pathlib.Path(".integrity")
    """The base directory where the archives are saved"""
    
    temp_directory = pathlib.Path(tempfile.gettempdir())

    path_to_monitor = pathlib.Path(argv[1])
    
    archive_name = re.sub(r"[^A-Za-z0-9-_]", "_", str(path_to_monitor))

    if (base_directory / (archive_name + ".zip")).exists():
        # The path exists
        shutil.make_archive(str(temp_directory / archive_name), "zip", str(path_to_monitor), str(path_to_monitor))
        digest_matches = False
        with open(str(temp_directory / (archive_name + ".zip")), "rb") as currentarchive:
            with open(str(base_directory / (archive_name + ".zip")), "rb") as savedarchive:
                digest_matches = hashlib.file_digest(currentarchive, "sha512").hexdigest() == hashlib.file_digest(savedarchive, "sha512").hexdigest()
        if digest_matches:
            print("OK matches")
        else:
            print("WARN checksum match failed")
    else:
        shutil.make_archive(str(base_directory / archive_name), "zip", str(path_to_monitor), str(path_to_monitor))
        print("OK " + str(base_directory / (archive_name + ".zip")))

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
