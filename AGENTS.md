# Working on source-coop-cli

How this CLI behaves, so every command behaves the same way. Each rule names the code that already does it: use that rather than writing your own. `resource_commands_follow_the_cli_conventions` in `src/main.rs` checks the parts that can be checked mechanically.

## Keep the README in sync

`README.md` is the user guide, and it must describe the CLI as it is. Any change to what a user can see or do updates it **in the same commit**:

- **Commands and flags:** new ones get an example. Changed or removed ones are changed or removed there too.
- **Behaviour:** prompts, keys, output formats and defaults.
- **Files and environment variables** it reads or writes.

Before committing, read the README sections your change touches and fix anything now untrue, including text written before your change. The README isn't a changelog: describe how the CLI works now, not what changed. `every_command_is_in_the_readme` in `src/main.rs` fails if a command is missing from it, but it can't tell whether the description is right. That part is on you.

## Help is the agents' documentation

Agents learn the CLI from `--help`, which always matches the installed version, so it has to stand on its own:

- **Every command and argument has a help line.** `every_command_and_argument_has_help` checks this.
- **Commands that change things show an example** in `after_help`, using `--json` and, where it applies, `-F -`. `help_examples_parse` checks that every example still parses.
- **Extra help text goes through `style::help`** (`style::examples` for examples), so its headings look like clap's. `help_headings_are_styled_like_clap_s` checks this.
- **`FOR_SCRIPTS` in `src/main.rs`** (the end of `source-coop --help`) sums up `--json`, prompts and exit codes. Keep it in step with the README and the JSON rules below.
- **No separate agent guide.** Help is the reference and the README is the guide. A skill or `llms.txt` should say when to use the CLI and point to `--help`, not copy flags. This file is for contributors: agents that only use the CLI never see it.

## Commands

- **One shape per resource.** A resource (`product`, and later accounts or members) has `list`, `view`, `create`, `edit` and `delete` under one noun. Name records as `ACCOUNT/PRODUCT`.
- **Signing in lives under `auth`:** `auth login | status | logout | token`. `creds` stays top-level because people's AWS configs run `credential_process = source-coop creds`.
- **Renaming a command keeps the old name working** as a hidden command that runs the same code (`#[command(hide = true)]`, like top-level `login`). Scripts, docs and habits use the old name. The README shows only the new one, with a note that the old still works.
- **`-i` wherever a record is named or listed** (everything but `create`, which prompts anyway). It opens the picker, or the record's screen when the record is named. With a name omitted, it picks one first. The test checks this.
- **`--json` on every read** (`list`, `view`), carrying the whole record. The test checks this. Writes take `--json` too.
- **Environments come from `--proxy-url` / `SOURCE_PROXY_URL`**, via `cache::env`. Every cached slot (login session, role credentials) is per environment. Production keeps the bare names so logins survive upgrades.

## Input

- **Precedence:** flags win over `-F/--from-file PATH` (`-` for stdin), which wins over prompts.
- **Prompt only when someone is there to answer:** `prompt::tty()` returns None without a terminal on stdin and stderr, or with `SOURCE_PROMPT_DISABLED` set. Then send what was given and let the API say what's missing. `delete` needs `--yes`.
- **The API is the only judge.** Don't validate locally. Show its field errors and ask again for just those fields (`send_until_accepted` / `reask` in `src/product.rs`). The one exception mirrors a server rule only to choose what to offer (`creatable_accounts`).
- **Defaults match the web UI's form**, for example a title made from the ID, and only the data connections and visibilities that are actually allowed.

## Prompts and interactive flows

Everything goes through the `Prompter` trait (`src/prompt.rs`), so tests can script it.

- **Sign in first.** Any create, edit or delete that prompts calls `client.check_signed_in()` before its first question, so nobody fills in a form only to be refused.
- **Questions are steps you can go back through.** ↑ (or ← at the start of a line) in text, and ← in a list, returns to the question before, starting from the answer given there; later answers are kept. Use the `*_or_back` methods, and model new flows on `ask_create`'s `Step`/`Next` loop. Fields answered by a flag, file or draft are skipped in both directions.
- **Review before creating.** Once a flow has asked anything, show what it will send and ask to confirm (`confirm_or_back`, `review_lines`). ← goes back from there too.
- **Typed confirmation before anything irreversible:** `prompt::confirm_by_name`.
- **Backing out:**
  - Esc (or `q` on a choice) is `prompt::CANCELLED`: nothing is changed.
  - Ctrl+C is `prompt::INTERRUPTED`, exit 130.
  - Neither prints "Error:". Report every error through `prompt::report` / `fail()` in `main.rs`, never with `eprintln!("Error: …")`.
- **Keep answers when a send fails.** Prompted sends go through `draft::Draft`: `resume()` before asking, `finish()` with the result. Drafts live in the OS state dir, not the cache.

## The `-i` picker

`src/picker.rs`, driven through `Prompter::browse` / `keypress`.

- **Keys:** ↑/↓ (`k`/`j`), PgUp/PgDn and Home/End move. → or Enter opens. ← or Esc (`h`/`q`) goes back, and quits from the top. `/` filters, and searches the server where the listing supports it. `b` opens the record in the browser.
- **Changing things only from a record's screen.** `e` and `d` (edit, delete) work after opening a record, not from the list, so you see the whole record first. Shortcuts run the commands' own code (`act`), never a second implementation.
- **Lists page themselves** as you near the end (`Action::More`). There's no "Load more…" entry.
- **Full screen:** `-i` runs on the alternate screen (`picker::FullScreen`) and restores the terminal however it ends. Outcomes appear as notices on the redrawn screen, not printed and then wiped.

## Output

- **Data on stdout, messages on stderr**, so `url=$(source-coop product create …)` works.
- **For people on a terminal, for scripts when piped.**
  - On a terminal, lists stream through the pager (`SOURCE_PAGER`, `PAGER`, then `less -FRX`; `--no-pager` turns it off).
  - Piped output and `--json` are for scripts: keep them stable.
- **Color only through `src/style.rs`** (`style::wanted`, `on_stderr`, `paint`, `id`): only on a terminal, and as `console` decides (never with `NO_COLOR` or `CLICOLOR=0`). Don't check the environment yourself. IDs are gray.
- **Show chosen fields, not every stored attribute.** Records carry internal leftovers; `data_mode` was one. Human output lists chosen fields with labels (`product_lines`). `--json` carries everything.

### JSON output

Scripts and AI agents use the CLI through `--json`, so it is a contract, not a second layout.

- **Every command that reports information takes `--json`:** reads, writes (the resulting record), `auth status`. Exceptions, which already print machine output or none of their own: `creds` (`--format`), `exec` (its command's output), `auth token` (a bare token), `auth login` (a browser sign-in; `auth status --json` reports the result), `api` (the API's response) and `-i` modes (interactive; `list --json` is their counterpart).
- **One JSON document on stdout and nothing else there.** Progress and notes go to stderr. No color, no padding, no pager.
- **Field names are the API's** (`account_id`, `created_at` in RFC 3339), plus derived fields only where they spare scripts work (`"expired": true`). Never human renderings like "3 years ago".
- **Adding fields is fine. Renaming or removing one is a breaking change.** Human output may change freely.
- **Print through `output::json`.** Don't hand-roll `serde_json` printing in a command.
- **Errors under `--json` are JSON too**, on stderr: `{"error": {"code", "message", "status"?, "field_errors"?}}`, the API's error shape. `fail(e, json)` in `main.rs` does it, using `failure::classify`. A command passes whether `--json` was asked for.
- **Exit codes mean the same everywhere** (`failure::Failure::exit_code`):

  | Code | Meaning |
  |------|---------|
  | 0 | Success |
  | 1 | Any other failure, including cancelling a prompt |
  | 2 | Bad command-line usage (clap) |
  | 3 | The API rejected the input (400, 409, 422): fix the named fields and retry |
  | 4 | Not signed in, or not allowed (401, 403) |
  | 5 | Not found (404) |
  | 130 | Interrupted (Ctrl+C) |

## Stored data

- Don't break a stored format (cache entries, sessions, drafts) without a way to read the old one.
- Secrets in files are created `0600` (`cache::write_file`). The login session's refresh token stays in the keyring.

## Testing

- **Before pushing:** `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo test --features staging`.
- **Interactive flows** are tested with the scripted prompter (`prompt::scripted::Script`) against `api_server()`, which mocks `/whoami`. Check the full `asked` list, so a new or reordered question shows up in review.
- **Never touch the real macOS keychain**, in tests or manual runs: a new build makes macOS ask for your password. Use made-up role names, a temp `HOME`, or a local stub API.
- **Never run a pager under a pty** unless it exits on its own (`PAGER='head -5'`) or with `--no-pager`, or the run hangs.

## Git

- Squash-merge with the PR title; release-please reads it.
- Use `--force-with-lease` pinned to the expected commit only for rebases. Otherwise push plainly.
- Read a pushed commit's hash from the push output before reporting it.

## Pull request descriptions

A reviewer should see what a change is like to use without building it. A PR that changes what a user can see or do has these sections, in this order. Leave out the ones with nothing to say.

1. **A paragraph on what users can now do**, then the commands as a `bash` block of examples, one per command or flag, with a comment where it isn't obvious.
2. **How it behaves:** prompts and their order, confirmations, what `--json` prints, exit codes, and anything a script relies on.
3. **Demos:** one recording for each command or flow in the change (below).
4. **Not in this PR:** what was deliberately left out, why, and when it would be worth adding.
5. **Follow-ups elsewhere**, such as source.coop server changes the CLI works around. Name the file and the problem.
6. **Testing:** the commands run and how many tests were added, and what wasn't tried, such as a real or staging API. Say it plainly.

### Demos

Record with `demo/` (see `demo/README.md`). Recordings are asciicasts uploaded to asciinema.org, where a reviewer can pause, rewind and copy the text.

- **One demo per command or flow,** each with a bold title. Show the interactive paths: prompts, ← back, the review, and `-i` screens with their keys. Show the failure paths too: a refusal, a typed confirmation typed wrong, and an exit code (`; echo "exit $?"`). Pipe `--json` through `jq -c` to keep it short.
- **Paste what `record.py --upload` prints:** `[![name](https://asciinema.org/a/ID.svg)](https://asciinema.org/a/ID)`. GitHub shows the SVG as a still of the last frame, and it links to the player. Don't commit GIFs or video: GitHub plays video only when it's dragged into the web editor, so scripts can't add it.
- **Say in the PR that the demos run against the stub,** so the `http://localhost:PORT` URLs in them aren't mistaken for real ones.
- **Uploads are public to anyone with the link.** Record only the stub's made-up data, never a real account or token. Uploads belong to the machine's asciinema install ID, and asciinema.org may delete those not linked to an account. Run `asciinema auth` once to link yours.
- **Recording is a review pass.** An awkward message or a screen titled wrongly in a demo is a bug: fix it in the PR and re-record.

### The stub server

`demo/stub.py` stands in for the source.coop API when recording. It isn't for tests, which mock the API with `wiremock`.

- **What it is:** stdlib Python, `python3 -I demo/stub.py PORT [FIXTURES]`, listening only on 127.0.0.1 and serving under `/api/v1`. `record.py` starts a fresh one on a free port for each demo, so every demo starts from `fixtures.json` as written. Within a demo, what one command creates, edits or deletes is what the next command sees, and it's gone when the stub stops.
- **Isolation:** each session gets `SOURCE_TOKEN=demo` (any token works), `SOURCE_API_URL` pointing at the stub, and a throwaway `HOME`. So the CLI never reads the real login session or the OS keychain, and drafts land in the throwaway `HOME`. Don't point a demo at a real environment instead.
- **Fixtures:** made-up records only. The signed-in `demo-user` owns the organization `demo-org`, with products, data connections, service accounts, trusts and memberships. Add the records a new demo needs to `fixtures.json`, keeping the names obviously fake.
- **It answers only what's been needed so far.** Anything else gets a 404 saying `The demo stub has no METHOD PATH`, so a missing endpoint is plain from the recording. Add a branch to `handle()` for each new path.
- **Match the API's shapes, not the CLI's guesses.** Take paths, bodies, status codes and response shapes from the OpenAPI spec (`https://source.coop/api/openapi`) or source.coop's `src/app/api/v1` routes. For example, membership lists come back as plain JSON arrays, while product lists come in pages (`{"items", "next_cursor"}`). A stub that answers in a shape the API doesn't use would make the demo show behaviour real users never see.
- **It checks almost nothing.** It returns the API's error shape (`{"error": {"code", "message", "field_errors"?}}`) only where a demo needs to show a refusal, such as a 409 for an ID that's taken. Add those per demo rather than reimplementing the API's rules.
