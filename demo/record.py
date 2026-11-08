"""Record terminal demos of the CLI as asciicasts, for PR descriptions.

Each demo runs bash in a pseudo-terminal against demo/stub.py, with a fresh
copy of the fixtures, a throwaway HOME, SOURCE_TOKEN set and an environment
of its own, so it never reads or changes the real login session. It types and presses keys like a
person, and the recording keeps the real timing (idle time capped).

    python3 -I demo/record.py SCRIPT [--bin DIR] [--out DIR] [NAME ...]

SCRIPT defines DEMOS = {name: (title, function)}; each function drives a
`Session` (see demo/README.md). Each cast is also rendered as an
animated SVG, and markdown showing the SVGs is printed for a PR
description: `gh pr create/edit --attach` uploads them.
"""

import argparse, fcntl, json, os, pty, re, runpy, shutil, socket, struct
import subprocess, sys, tempfile, termios, threading, time

# 80 columns keeps the text close to the docs site's body text (about 15px
# against 16px) at the width it shows demos; svg-term draws a column 10px wide.
COLS, ROWS = 80, 28
KEYS = {"DOWN": "\x1b[B", "UP": "\x1b[A", "RIGHT": "\x1b[C", "LEFT": "\x1b[D",
        "ESC": "\x1b", "BACKSPACE": "\x7f"}
ANSI = re.compile(r"\x1b(\[[0-9;?]*[ -/]*[@-~]|[()][0-9A-Za-z]|[=>78])")


class Session:
    """bash in a pty, recorded from start to the last prompt."""

    def __init__(self, title, env, cwd):
        self.title, self.events, self.text, self.seen = title, [], "", 0
        # Steps for the docs player: each command run, and each prompt a key
        # answers, labelled with what was on screen and the keys pressed.
        self.steps, self.pending, self.quiet = [], None, False
        # Each key pressed (not text typed), for the player's key overlay.
        self.keys = []
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

    def see(self, pattern, timeout=20, step=None):
        """Wait for `pattern` (a regex) in what has appeared since the last wait.
        If a key answers it, that's a step in the docs player, labelled `step`,
        or the pattern when it's plain words, or else the line it matched."""
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                stripped = ANSI.sub("", self.text[self.seen:])
                m = re.search(pattern, stripped)
                if m:
                    plain = re.fullmatch(r"[\w ,.'-]+", pattern) and pattern
                    self.pending = (time.time() - self.t0, step or plain or prompt_line(stripped, m))
                    # Only what the match covers counts as seen, so text that
                    # arrived with it, like the next prompt, is left to wait for.
                    self.seen = after_visible(self.text, self.seen, m.end())
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

    def act(self, did):
        """Note an input for the steps: it answers the prompt last seen."""
        if self.quiet:
            return
        if self.pending:
            t, label = self.pending
            self.steps.append({"t": t, "label": label, "did": []})
            self.pending = None
        if self.steps:
            self.steps[-1]["did"].append(did)

    def type(self, text, before=0.4):
        self.pause(before)
        self.act(json.dumps(text, ensure_ascii=False))
        for c in text:
            self.send(c)
            time.sleep(0.045)

    def run(self, command):
        """Type a command at the prompt and run it."""
        self.pending, self.quiet = None, True
        self.steps.append({"t": time.time() - self.t0 + 0.7, "label": "$ " + command, "did": []})
        self.type(command, 0.7)
        self.pause(0.5)
        self.send("\r")
        # Skip the shell's echo of the command, so a wait for text in the
        # command itself waits for the command's output instead.
        # ponytail: the first newline is the Enter; a command too long for
        # one line could wrap before it.
        self.see(r"\n")
        self.pending, self.quiet = None, False

    def enter(self):
        self.pause(0.6)
        self.act("Enter")
        self.keys.append({"t": time.time() - self.t0, "key": "Enter"})
        self.send("\r")

    def key(self, keys, times=1):
        name = NAMES.get(keys) or NAMES.get(keys[:1], keys) + (f"×{len(keys)}" if len(keys) > 1 else "")
        self.act(name + (f"×{times}" if times > 1 else ""))
        for _ in range(times):
            self.pause(0.4)
            if not self.quiet:
                self.keys.append({"t": time.time() - self.t0, "key": name})
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
        # The steps, on the SVG's timeline: svg-term caps each pause at the
        # cast's idle_time_limit, so the same cap maps wall-clock times onto it.
        times = [e[0] for e in kept]
        def capped(t):
            at, prev = 0.0, 0.0
            for e in times:
                if e > t:
                    break
                at, prev = at + min(e - prev, 2.5), e
            return at + min(max(t - prev, 0), 2.5)
        steps = [{"time": round(capped(s["t"]), 3),
                  "label": " · ".join(filter(None, [s["label"], " ".join(s["did"])]))} for s in self.steps]
        with open(path.removesuffix(".cast") + ".json", "w") as f:
            keys = [{"time": round(capped(k["t"]), 3), "key": k["key"]} for k in self.keys]
            json.dump({"duration": round(capped(times[-1]), 3), "steps": steps, "keys": keys}, f, ensure_ascii=False, indent=1)


NAMES = {"\x1b[B": "↓", "\x1b[A": "↑", "\x1b[C": "→", "\x1b[D": "←", "\x1b": "Esc", "\x7f": "⌫",
         "\t": "Tab", "\r": "Enter"}


def prompt_line(text, m):
    """The screen line a match is on, as a step's label: the prompt, without
    its marks and key hints. ponytail: full-screen views redraw with cursor
    moves, so their "line" can hold more than one row; good enough to tell
    steps apart."""
    a, b = text.rfind("\n", 0, m.start()) + 1, text.find("\n", m.end())
    line = text[a:b if b != -1 else len(text)].replace("\r", " ")
    line = re.split(r" ›| \[|  +(?=\S)", line.strip(" ?✔›>\t"))[0]
    return " ".join(line.split())[:60]


def after_visible(text, start, count):
    """The index in `text` just past `count` visible (non-ANSI) characters from `start`."""
    i = start
    while count and i < len(text):
        m = ANSI.match(text, i)
        if m:
            i = m.end()
        else:
            i, count = i + 1, count - 1
    return i


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
    stub_url = f"http://127.0.0.1:{port}"
    try:
        wait_for(port)
        env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": home,
               "TERM": "xterm-256color", "LANG": "en_US.UTF-8", "SOURCE_TOKEN": "demo",
               "SOURCE_API_URL": stub_url,
               # The cache keys the keyring and its files by environment, and HOME
               # doesn't change the keyring, so an environment of the run's own keeps
               # demos away from the real login. ponytail: a demo that saves a session
               # or credentials still leaves an entry for 127.0.0.1:PORT in the
               # keyring; switching the keyring off would need a setting in the CLI.
               "SOURCE_PROXY_URL": stub_url,
               # The pager would wait for a key on a list taller than the screen.
               "SOURCE_PAGER": "cat",
               "BASH_SILENCE_DEPRECATION_WARNING": "1",
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
    # Only inside tags: the recorded text may say class="…" or style too, and
    # it can't contain a raw "<", so a tag is everything from "<" to ">".
    tags = lambda f: re.sub(r"<[^>]*>", lambda t: f(t[0]), s)
    s = tags(lambda t: re.sub(r'class="([^"]*)"', attributes, t).replace(' style="white-space:pre"', ""))
    s = s.replace("<svg ", '<svg xml:space="preserve" ', 1)
    left = re.findall(r"<style|\sstyle=", "".join(re.findall(r"<[^>]*>", s)))
    assert not left and "animateTransform" in s, "svg-term wrote CSS this can't rewrite"
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
