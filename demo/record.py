"""Record terminal demos of the CLI as asciicasts, for PR descriptions.

Each demo runs bash in a pseudo-terminal against demo/stub.py, with a fresh
copy of the fixtures, a throwaway HOME and SOURCE_TOKEN set, so it never
reads the real login session or keychain. It types and presses keys like a
person, and the recording keeps the real timing (idle time capped).

    python3 -I demo/record.py SCRIPT [--bin DIR] [--out DIR] [--upload] [NAME ...]

SCRIPT defines DEMOS = {name: (title, function)}; each function drives a
`Session` (see demo/demos/products.py). Each cast is also rendered as a GIF
with agg, when it's installed. --upload sends each cast to asciinema.org,
where anyone with the link can watch it, and prints markdown for a PR
description: the GIF, served from --gif-base, linking to the player.
"""

import argparse, fcntl, json, os, pty, re, runpy, shutil, socket, struct
import subprocess, sys, tempfile, termios, threading, time

COLS, ROWS = 120, 34
KEYS = {"DOWN": "\x1b[B", "UP": "\x1b[A", "RIGHT": "\x1b[C", "LEFT": "\x1b[D",
        "ESC": "\x1b", "BACKSPACE": "\x7f"}
ANSI = re.compile(r"\x1b(\[[0-9;?]*[ -/]*[@-~]|[()][0-9A-Za-z]|[=>78])")


class Session:
    """bash in a pty, recorded from start to the last prompt."""

    def __init__(self, title, env, cwd):
        self.title, self.events, self.text, self.seen = title, [], "", 0
        self.lock = threading.Lock()
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(cwd)
            os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-i"], env)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
        self.pid, self.fd, self.t0 = pid, fd, time.time()
        threading.Thread(target=self._read, daemon=True).start()
        self.prompt()

    def _read(self):
        while True:
            try:
                data = os.read(self.fd, 65536)
            except OSError:
                return
            if not data:
                return
            text = data.decode("utf-8", "replace")
            with self.lock:
                self.events.append([round(time.time() - self.t0, 6), "o", text])
                self.text += text

    def see(self, pattern, timeout=20):
        """Wait for `pattern` (a regex) in what has appeared since the last wait."""
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                if re.search(pattern, ANSI.sub("", self.text[self.seen:])):
                    # ponytail: everything so far counts as seen; each wait is
                    # for something new, so nothing needs a precise offset.
                    self.seen = len(self.text)
                    return
            time.sleep(0.05)
        tail = ANSI.sub("", self.text[-1500:])
        raise SystemExit(f"{self.title}: never saw {pattern!r}. The screen ended:\n{tail}")

    def prompt(self):
        """Wait for the shell's prompt: the command before has finished."""
        self.see(r"\$ $")

    def pause(self, seconds):
        time.sleep(seconds)

    def send(self, keys):
        os.write(self.fd, keys.encode())

    def type(self, text, before=0.4):
        self.pause(before)
        for c in text:
            self.send(c)
            time.sleep(0.045)

    def run(self, command):
        """Type a command at the prompt and run it."""
        self.type(command, 0.7)
        self.pause(0.5)
        self.send("\r")

    def enter(self):
        self.pause(0.6)
        self.send("\r")

    def key(self, keys, times=1):
        for _ in range(times):
            self.pause(0.4)
            self.send(keys)

    def finish(self, path):
        """Wait for the last command, then save the cast and close the shell."""
        self.prompt()
        self.pause(2.5)
        with self.lock:
            self.events.append([round(time.time() - self.t0, 6), "o", ""])
            kept = list(self.events)
        self.send("exit\r")
        os.waitpid(self.pid, 0)
        header = {"version": 2, "width": COLS, "height": ROWS, "timestamp": int(self.t0),
                  "idle_time_limit": 2.5, "title": self.title,
                  "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}}
        with open(path, "w") as f:
            f.write(json.dumps(header) + "\n")
            f.writelines(json.dumps(e) + "\n" for e in kept)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(port):
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise SystemExit("the stub didn't start")


def record(name, title, fn, bin_dir, out):
    here = os.path.dirname(os.path.abspath(__file__))
    port = free_port()
    stub = subprocess.Popen([sys.executable, "-I", os.path.join(here, "stub.py"), str(port)])
    home = tempfile.mkdtemp(prefix="source-coop-demo-")
    try:
        wait_for(port)
        env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": home,
               "TERM": "xterm-256color", "LANG": "en_US.UTF-8", "SOURCE_TOKEN": "demo",
               "SOURCE_API_URL": f"http://localhost:{port}", "BASH_SILENCE_DEPRECATION_WARNING": "1",
               "PS1": "\\[\\e[1;32m\\]$\\[\\e[0m\\] "}
        session = Session(title, env, home)
        fn(session)
        path = os.path.join(out, f"{name}.cast")
        session.finish(path)
        return path
    finally:
        stub.kill()
        stub.wait()
        shutil.rmtree(home, ignore_errors=True)


def gif(cast):
    """The cast as an animated GIF beside it, or None without agg."""
    if not shutil.which("agg"):
        return None
    out = cast.removesuffix(".cast") + ".gif"
    subprocess.run(["agg", "--font-size", "14", "--idle-time-limit", "2.5", "--last-frame-duration", "4",
                    cast, out], check=True, capture_output=True)
    return out


def upload(path):
    done = subprocess.run(["asciinema", "upload", path], capture_output=True, text=True, check=True)
    # asciinema prints the URL on stderr or stdout, depending on its version.
    url = re.search(r"https://asciinema\.org/a/\w+", done.stdout + done.stderr)
    if not url:
        raise SystemExit(f"asciinema didn't say where {path} went:\n{done.stdout}{done.stderr}")
    return url[0]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("script", help="a demo script defining DEMOS")
    p.add_argument("names", nargs="*", help="which demos to record (all when omitted)")
    p.add_argument("--bin", default="target/debug", help="the directory holding source-coop [target/debug]")
    p.add_argument("--out", default="demo/casts", help="where to write the .cast files [demo/casts]")
    p.add_argument("--upload", action="store_true", help="upload each cast to asciinema.org and print markdown")
    p.add_argument("--gif-base", help="with --upload: the URL the GIFs will be served from, e.g. "
                   "https://github.com/source-cooperative/source-coop-cli/raw/demo-assets/pr-60")
    args = p.parse_args()
    if args.upload and not args.gif_base:
        # GitHub's image proxy can't fetch asciinema.org's previews, so a PR
        # shows GIFs served from GitHub, linking to the player.
        p.error("--upload needs --gif-base: where the GIFs will be served (see demo/README.md)")
    demos = runpy.run_path(args.script, init_globals=dict(KEYS))["DEMOS"]
    bin_dir = os.path.abspath(args.bin)
    if not os.path.exists(os.path.join(bin_dir, "source-coop")):
        raise SystemExit(f"no source-coop in {bin_dir}: run `cargo build` first, or pass --bin")
    os.makedirs(args.out, exist_ok=True)
    markdown = []
    for name in args.names or demos:
        title, fn = demos[name]
        path = record(name, title, fn, bin_dir, args.out)
        print(f"recorded {path}", file=sys.stderr)
        rendered = gif(path)
        if rendered:
            print(f"rendered {rendered}", file=sys.stderr)
        if args.upload:
            url = upload(path)
            image = f"{args.gif_base.rstrip('/')}/{name}.gif"
            markdown += [f"**{title}**", "", f"[![{name}]({image})]({url})", ""]
    if markdown:
        print("\n".join(markdown))


if __name__ == "__main__":
    main()
