# Recording demos for PR descriptions

`demo/` records terminal demos of the CLI as [asciicasts](https://docs.asciinema.org/manual/asciicast/v2/), so a PR can show what a change looks like to use. Each recording runs against a stub of the source.coop API filled with made-up records, so nothing touches a real account or a real login.

```bash
cargo build
# write demo/scripts/pr-60.py for your change (see "Writing a demo"), then:
python3 -I demo/record.py demo/scripts/pr-60.py                     # every demo in the script, to demo/casts/
python3 -I demo/record.py demo/scripts/pr-60.py product-create      # just one
```

It needs Python 3.10 or later on macOS or Linux, and Node.js for `npx`, which fetches [svg-term-cli](https://github.com/marionebl/svg-term-cli) 2.1.1 to render the SVGs. Putting them in a PR needs [`gh`](https://cli.github.com) 2.103 or later. Demos that pipe through `jq` need it installed.

## What's here

- `stub.py` serves `fixtures.json` under `/api/v1` from memory. What a demo creates, edits or deletes, the commands after it see. Every demo starts from a fresh copy. It answers what the CLI asks, in the API's shapes, and checks nothing: it is for demos, not tests, which use `wiremock`.
- `fixtures.json` holds the records: the signed-in `demo-user`, who owns the organization `demo-org`, with its products, data connections, service accounts, trusts, API keys and memberships. Add what a new demo needs here.
- `check_stub.py` makes a request to each of the stub's routes and validates the answers against the API's OpenAPI spec on staging. CI runs it on PRs that change `demo/`. Run it yourself after changing the stub or fixtures: `uv run --with jsonschema python demo/check_stub.py` (or `pip install jsonschema` first). When a demo needs a new route, add a request for it to `requests()`.
- `record.py` runs bash in a pseudo-terminal at 80×28 and types each demo's commands like a person. It records with real timing, capping idle time at 2.5s. The recording ends at the last prompt, and each is rendered as an animated SVG beside its cast, with its steps in a JSON file of the same name. The docs site's player marks the steps on its track and lists them: each command run, and each prompt that a key answers.
- `demos/` holds the scripts for the demos the README shows, which are kept in `docs/demos/` (below).
- No other demo scripts are kept. Each PR writes its own, for what it changes, in `demo/scripts/`, which git ignores. A script that isn't run between PRs only goes stale, and whoever made a change knows what to show of it.

## Writing a demo

A script is a Python file defining `DEMOS = {name: (title, function)}`, where each function drives a `Session`. `record.py` provides `DOWN`, `UP`, `RIGHT`, `LEFT`, `ESC` and `BACKSPACE`.

```python
# demo/scripts/pr-60.py
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


DEMOS = {"product-create": ("source-coop product create (prompted)", create)}
```

Write one demo for each command or flow the PR changes, showing what changed: prompts and their order, `-i` screens and their keys, refusals and exit codes. Add whatever the demos need to `stub.py` and `fixtures.json`. Those are kept, so the next PR starts from them.

Wait with `see` before every keypress that answers a prompt. That prompt and the keys that answer it make one step in the docs player, labelled with the text you waited for when it's plain words, or else with the line it matched. Name a step yourself with `s.see("Landsat", step="The list")` when neither says what's on screen, as on an `-i` screen. Run each command after the first with `s.prompt()` in between, so it waits for the one before. If a `see` never matches, recording stops and prints the end of the screen.

Each session gets `SOURCE_TOKEN=demo`, `SOURCE_API_URL` and `SOURCE_PROXY_URL` pointing at the stub, `SOURCE_PAGER=cat` and a throwaway `HOME`. The proxy URL gives the run an environment of its own: the CLI keys its keyring entries and cache files by environment, so it can't read or remove the real login session, and drafts land in the throwaway `HOME`. A demo that saves a session or credentials still writes an entry for that environment (`127.0.0.1:PORT`) to the OS keyring, so leave sign-in out of demos. The one thing that does reach the network is the CLI's own lookups elsewhere, such as a GitHub repository's subject claim. Use a public repository for those, like `source-cooperative/source.coop`.

## In the README

The README embeds animated SVGs from `docs/demos/`, the only recordings git keeps. `demos/guide.py` makes most of them and `demos/service-accounts.py` the service-account section's. When a change alters what one shows, update its script and re-record just that demo, then check the SVG shows what the README says it does:

```bash
cargo build
python3 -I demo/record.py demo/demos/guide.py --out docs/demos product-create
python3 -I demo/record.py demo/demos/service-accounts.py --out docs/demos/service-account keys
rm docs/demos/*.cast docs/demos/service-account/*.cast    # keep the .svg and .json
```

A new demo needs a line in the script's `DEMOS` and an image in the README. Each SVG is one to four hundred kilobytes, and every re-recording adds another copy to git's history, so re-record what changed rather than everything.

## In a PR description

`record.py` prints markdown showing each SVG by its local path. `gh` uploads the files you `--attach` and rewrites those paths to point at the uploads, so the SVGs live on GitHub with the PR and nothing else hosts them:

```bash
python3 -I demo/record.py demo/scripts/pr-60.py > demos.md
# write the description in body.md, pasting demos.md where the demos go, then:
attach=(); for f in demo/casts/*.svg; do attach+=(--attach "$f"); done
gh pr create -F body.md "${attach[@]}"                 # or: gh pr edit 60 -F body.md "${attach[@]}"
```

Each entry looks like this before `gh` rewrites it:

```markdown
**source-coop product create (prompted)**

![source-coop product create (prompted)](demo/casts/product-create.svg)
```

Run `gh` from the repository root, or keep `body.md` there: `gh` reads the paths relative to the body file, then to the working directory. URLs in the demos name the stub (`http://127.0.0.1:PORT`): say so in the PR.

svg-term animates its SVGs with CSS, and GitHub serves attachments with a Content-Security-Policy that blocks CSS when an SVG is opened on its own (inside the PR it's an image, and animates either way). So `record.py` rewrites the CSS as an SVG `<animateTransform>` and `fill`/`font-weight` attributes, which the policy allows. That rewrite knows only svg-term 2.1.1's output: if a new version writes CSS it doesn't recognise, recording stops with an error.
