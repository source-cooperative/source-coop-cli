"""Replay a VHS tape's keystrokes into bash on its own pty, echoing what it
draws to stdout, so `asciinema rec -c "python3 drive.py TAPE"` records it.

Understands the tape commands the demos use: Type, Enter, Up/Down/Left/Right
(with a count), Escape, Sleep. Hide/Show blocks and settings are skipped:
setup comes from the environment instead.
"""
import fcntl
import os
import pty
import re
import select
import struct
import sys
import termios
import time

tape, port = sys.argv[1], sys.argv[2]
DEMO = os.path.dirname(os.path.abspath(__file__))
KEYS = {"Enter": b"\r", "Up": b"\x1b[A", "Down": b"\x1b[B", "Right": b"\x1b[C",
        "Left": b"\x1b[D", "Escape": b"\x1b"}
COLS, ROWS = 130, 30

pid, fd = pty.fork()
if pid == 0:
    os.chdir(os.path.join(DEMO, "work"))
    env = {"PATH": f"{DEMO}/bin:/opt/homebrew/bin:/usr/bin:/bin", "HOME": os.path.join(DEMO, "work"),
           "TERM": "xterm-256color", "LANG": "en_US.UTF-8", "PS1": "$ ", "PAGER": "cat",
           "SOURCE_API_URL": f"http://127.0.0.1:{port}", "SOURCE_TOKEN": "demo",
           "BASH_SILENCE_DEPRECATION_WARNING": "1"}
    os.execve("/bin/bash", ["bash", "--norc", "--noprofile"], env)

fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))


def pump(seconds):
    """Copy the shell's output to stdout for `seconds`."""
    end = time.time() + seconds
    while (left := end - time.time()) > 0:
        r, _, _ = select.select([fd], [], [], left)
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                return
            os.write(1, data)


def seconds(s):
    return float(s[:-2]) / 1000 if s.endswith("ms") else float(s.rstrip("s"))


pump(0.5)
hidden = False
for line in open(tape):
    line = line.strip()
    word, _, rest = line.partition(" ")
    if word == "Hide":
        hidden = True
    elif word == "Show":
        hidden = False
    elif hidden or word in ("", "Output", "Source", "Set"):
        continue
    elif word == "Type":
        text = re.match(r'^(["`])(.*)\1$', rest).group(2)
        for ch in text:
            os.write(fd, ch.encode())
            pump(0.035)
    elif word in KEYS:
        for _ in range(int(rest or 1)):
            os.write(fd, KEYS[word])
            pump(0.15)
    elif word == "Sleep":
        pump(seconds(rest))
# End without typing exit, which would show.
os.kill(pid, 9)
