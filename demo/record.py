"""Record terminal demos of the CLI as asciicasts, for PR descriptions.

Each demo runs bash in a pseudo-terminal against demo/stub.py, with a fresh
copy of the fixtures, a throwaway HOME and SOURCE_TOKEN set, so it never
reads the real login session or keychain. It types and presses keys like a
person, and the recording keeps the real timing (idle time capped).

    python3 -I demo/record.py SCRIPT [--bin DIR] [--out DIR] [NAME ...]

SCRIPT defines DEMOS = {name: (title, function)}; each function drives a
`Session` (see demo/README.md). Each cast is also rendered as an
animated SVG, and markdown showing the SVGs is printed for a PR
description: `gh pr create/edit --attach` uploads them.
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


def svg(cast):
    """The cast as an animated SVG beside it, made with svg-term (via npx).

    svg-term animates with CSS, which GitHub's CSP blocks when the SVG is
    opened on its own, so the CSS is rewritten as SMIL and attributes."""
    if not shutil.which("npx"):
        raise SystemExit("rendering SVGs needs npx: install Node.js")
    out = cast.removesuffix(".cast") + ".svg"
    subprocess.run(["npx", "-y", "svg-term-cli@2.1.1", "--in", cast, "--out", out, "--window"],
                   check=True, capture_output=True)
    with open(out) as f:
        text = without_css(f.read())
    with open(out, "w") as f:
        f.write(text)
    return out


def without_css(s):
    """svg-term's SVG with its <style> rewritten as SMIL and presentation
    attributes. ponytail: matches svg-term 2.1.1's output only; the assert
    says when a new version writes CSS this doesn't know."""
    css = "".join(re.findall(r"<style>(.*?)</style>", s, re.S))
    css = re.sub(r"\bfrom\{", "0%{", re.sub(r"\bto\{", "100%{", css))
    s = re.sub(r"<style>.*?</style>", "", s, flags=re.S)
    # The animation: a filmstrip of frames, slid left in steps.
    kf = re.search(r"@keyframes \w+\{((?:[\d.]+%\{[^}]*\})+)\}", css)
    stops = re.findall(r"([\d.]+)%\{transform:translateX\((-?[\d.]+)(?:px)?\)\}", kf[1])
    css = css.replace(kf[0], "")
    smil = ('<animateTransform attributeName="transform" type="translate" calcMode="discrete" '
            'dur="{}" repeatCount="indefinite" keyTimes="{}" values="{}"/>').format(
        "{}", ";".join(f"{float(p) / 100:g}" for p, _ in stops), ";".join(f"{x} 0" for _, x in stops))
    s = re.sub(r'<g style="[^"]*animation-duration:([\d.]+s)[^"]*">',
               lambda m: "<g>" + smil.format(m[1]), s, count=1)
    # Class rules become attributes; white-space:pre becomes xml:space.
    rules = {}
    for selectors, decls in re.findall(r"([^{}]+)\{([^}]*)\}", css):
        for sel in selectors.split(","):
            for d in filter(None, decls.split(";")):
                k, v = d.split(":", 1)
                if k != "white-space":
                    rules.setdefault(sel.strip().lstrip("."), {})[k] = v
    def attributes(m):
        merged = {}
        for c in m[1].split():
            merged.update(rules.get(c, {}))
        return " ".join(f'{k}="{v}"' for k, v in merged.items())
    s = re.sub(r'class="([^"]*)"', attributes, s).replace(' style="white-space:pre"', "")
    s = s.replace("<svg ", '<svg xml:space="preserve" ', 1)
    assert "style" not in s and "animateTransform" in s, "svg-term wrote CSS this can't rewrite"
    return s


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("script", help="a demo script defining DEMOS")
    p.add_argument("names", nargs="*", help="which demos to record (all when omitted)")
    p.add_argument("--bin", default="target/debug", help="the directory holding source-coop [target/debug]")
    p.add_argument("--out", default="demo/casts", help="where to write the .cast files [demo/casts]")
    args = p.parse_args()
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
        rendered = svg(path)
        print(f"rendered {rendered}", file=sys.stderr)
        # A local path: `gh pr create/edit --attach` uploads the file and
        # rewrites this reference to point at the upload.
        markdown += [f"**{title}**", "", f"![{title}]({rendered})", ""]
    print("\n".join(markdown))


if __name__ == "__main__":
    main()
