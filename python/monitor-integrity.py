"""
Archives files into ~/.integrity

Run again to monitor changes.

Copyright (c) 2024 UFSIT Blue Team.
"""

import hashlib
import os
import os.path
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
    
    archive_name = None
    monitor_directory = False  # Whether a directory is being monitored
    if os.path.isdir(path_to_monitor):
        archive_name = re.sub(r"[^A-Za-z0-9-_]", "_", str(path_to_monitor)) + ".zip"
        monitor_directory = True
    elif os.path.isfile(path_to_monitor):
        archive_name = re.sub(r"[^A-Za-z0-9-_]", "_", str(path_to_monitor))
    else:
        print("NOTFOUND File \"" + str(path_to_monitor) + "\" not found.")
        return 1

    if (base_directory / archive_name).exists():
        # The path exists
        digest_matches = False
        if monitor_directory:
            shutil.make_archive(str(temp_directory / archive_name)[:-4], "zip", str(path_to_monitor), str(path_to_monitor))
            with open(str(temp_directory / (archive_name)), "rb") as currentarchive:
                with open(str(base_directory / (archive_name)), "rb") as savedarchive:
                    digest_matches = hashlib.file_digest(currentarchive, "sha512").hexdigest() == hashlib.file_digest(savedarchive, "sha512").hexdigest()
        else:
            with open(str(path_to_monitor), "rb") as currentarchive:
                with open(str(base_directory / (archive_name)), "rb") as savedarchive:
                    digest_matches = hashlib.file_digest(currentarchive, "sha512").hexdigest() == hashlib.file_digest(savedarchive, "sha512").hexdigest()
        if digest_matches:
            print("CHECKPASS checksum atches")
        else:
            print("CHECKFAIL checksum match failed")
    else:
        base_directory.mkdir(parents=True, exist_ok=True)
        if monitor_directory:
            shutil.make_archive(str(base_directory / archive_name)[:-4], "zip", str(path_to_monitor), str(path_to_monitor))
        else:
            shutil.copy2(str(path_to_monitor), str(base_directory / archive_name))
        print("CREATED " + str(base_directory / archive_name))

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
