# Recording demos for PR descriptions

`demo/` records terminal demos of the CLI as [asciicasts](https://docs.asciinema.org/manual/asciicast/v2/), so a PR can show what a change looks like to use. Each recording runs against a stub of the source.coop API filled with made-up records, so nothing touches a real account or a real login.

```bash
cargo build
python3 -I demo/record.py demo/demos/products.py                    # every demo in the script, to demo/casts/
python3 -I demo/record.py demo/demos/products.py product-create     # just one
python3 -I demo/record.py demo/demos/products.py --upload           # and upload them, printing markdown for the PR
```

It needs Python 3.10 or later on macOS or Linux, and, for `--upload`, [asciinema](https://asciinema.org) (`brew install asciinema`). Demos that pipe through `jq` need it installed.

## What's here

- `stub.py` serves `fixtures.json` under `/api/v1` from memory. What a demo creates, edits or deletes, the commands after it see. Every demo starts from a fresh copy. It answers what the CLI asks, in the API's shapes, and checks nothing: it is for demos, not tests, which use `wiremock`.
- `fixtures.json` holds the records: the signed-in `demo-user`, who owns the organization `demo-org`, with its products, data connections, service accounts, trusts and memberships. Add what a new demo needs here.
- `record.py` runs bash in a pseudo-terminal at 120×34 and types each demo's commands like a person. It records with real timing, capping idle time at 2.5s. The recording ends at the last prompt.
- `demos/*.py` are the scripts, one per area. Each defines `DEMOS = {name: (title, function)}`.

## Writing a demo

A demo is a function that drives a `Session`:

```python
def create(s):
    s.run("source-coop product create")   # type a command at the prompt and run it
    s.see("Account")                      # wait for text (a regex) to appear
    s.key(DOWN)                           # press keys: DOWN UP RIGHT LEFT ESC BACKSPACE, or any text
    s.enter()
    s.see("Product ID")
    s.type("sea-ice")                     # type, a character at a time
    s.enter()
    s.see("Create this product")
    s.pause(3)                            # give the viewer time to read
    s.enter()
```

Wait with `see` before every keypress that answers a prompt. Run each command after the first with `s.prompt()` in between, so it waits for the one before. If a `see` never matches, recording stops and prints the end of the screen.

Each session gets `SOURCE_TOKEN=demo`, `SOURCE_API_URL` pointing at the stub, and a throwaway `HOME`. So the CLI never reads the real login session or the OS keyring, and drafts land in the throwaway `HOME`. The one thing that does reach the network is the CLI's own lookups elsewhere, such as a GitHub repository's subject claim. Use a public repository for those, like `source-cooperative/source.coop`.

## In a PR description

`--upload` sends each cast to asciinema.org. Anyone with the link can watch it, so record only the stub's made-up data. It prints a block like this to paste:

```markdown
**source-coop product create (prompted)**

[![product-create](https://asciinema.org/a/ID.svg)](https://asciinema.org/a/ID)
```

GitHub shows the SVG as a preview of the recording's last frame, and clicking it plays the recording. URLs in the demos name the stub (`http://localhost:PORT`): say so in the PR.
