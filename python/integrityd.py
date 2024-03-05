import argparse
import pathlib
import subprocess
import sys
import time

timeformat = "%Y/%m/%d %H:%M:%S"

def main(argv: list[str]) -> int:
    argparser = argpase.ArgumentParser(description="Monitors files for changes")
    argparser.add_argument("--cmdline", "-c", help="Command line of the monitor-integrity binary. Defaults to ./monitor-integrity")
    argparser.add_argument("--logfile", "-l", help="File to log changes to")
    argparser.add_argument("--overwrite", "-o", action="store_false", help="Overwrite files without asking")
    argparser.add_argument("--trust", "-t", action="store_true",
                           help="Assume all files are good on start and ignore everything currently in the ~/.integrity folder")
    # TODO Add an argument specifying a list with files to monitor to pass in

    parsedargs = argparser.parse_args()

    monitor_integrity_exe = "./monitor-integrity"
    if parsedargs.cmdline:
        monitor_integrity_exe = parsedargs.cmdline
    
    log_file_name = None
    if parsedargs.logfile:
        log_file_name = parsedargs.logfile
    
    ask_before_overwrite = parsedargs.overwrite
    
    try:
        with open(log_file_name, 'x') as logfile:
            pass
    except FileExistsError:
        if ask_before_overwrite and input("File \"" + log_file_name + "\" already exists, overwrite? [y/N] ").lower() != "y":
            print("Not overwriting already existing file \"" + log_file_name + "\"")
            return 1

    try:
        while True:
            # TODO Run monitor-integrity on the list of files.
            time.sleep(20)
    except KeyboardInterrupt:
        print("Got Ctrl-C, now exiting...")

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
