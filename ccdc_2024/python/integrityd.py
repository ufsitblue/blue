import argparse
import datetime
import pathlib
import subprocess
import sys
import time

timeformat = "%Y/%m/%d %H:%M:%S"

def current_time_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")

def main(argv: list[str]) -> int:
    argparser = argparse.ArgumentParser(description="Monitors files for changes")
    argparser.add_argument("--cmdline", "-c", help="Command line of the monitor-integrity binary. Defaults to ./monitor-integrity")
    argparser.add_argument("--overwrite", "-o", action="store_false", help="Overwrite files without asking")
    argparser.add_argument("monitorfile", help="A file containing the names of files and directories to monitor")
    argparser.add_argument("logfile", help="File to log information to")
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
        if log_file_name:
            with open(log_file_name, 'x') as logfile:
                pass
    except FileExistsError:
        if ask_before_overwrite and input("File \"" + log_file_name + "\" already exists, overwrite? [y/N] ").lower() != "y":
            print("Not overwriting already existing file \"" + log_file_name + "\"")
            return 1

    try:
        while True:
            with open(log_file_name, 'w') as logfile:
                logfile.write("File integrity as of " + current_time_str() + "\n")
                with open(parsedargs.monitorfile, 'r') as monitorfile:
                    for filename in monitorfile:
                        filename = filename.strip()
                        integritycheck = subprocess.run(monitor_integrity_exe.split(' ') + [filename], capture_output=True)
                        logfile.write(filename + " - " + integritycheck.stdout.decode('utf-8') + "\n")
            time.sleep(20)
    except KeyboardInterrupt:
        print("Got Ctrl-C, now exiting...")

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
