#!/usr/bin/python3
# this script uses file descriptor "1" as input to open a binary
import subprocess
import os
import sys

with open("./random_input_file", "w") as f:
    saved_stdout_fd = os.dup(sys.stdout.fileno())
    with open(os.devnull, "w") as devnull:
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), 1)
        argv = ["/binary"] # change your binary here
        p = subprocess.Popen(argv, stdin=1, stdout=saved_stdout_fd, stderr=saved_stdout_fd, close_fds=False)
        p.wait()
        os.dup2(saved_stdout_fd, sys.stdout.fileno())
    os.close(saved_stdout_fd)
