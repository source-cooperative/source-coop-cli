# Working on source-coop-cli

How this CLI behaves, so every command behaves the same way. Each rule names the code that already does it: use that rather than writing your own. `resource_commands_follow_the_cli_conventions` in `src/main.rs` checks the parts that can be checked mechanically.

## Keep the README in sync

`README.md` is the user guide, and it must describe the CLI as it is. Any change to what a user can see or do updates it **in the same commit**:

- **Commands and flags:** new ones get an example. Changed or removed ones are changed or removed there too.
- **Behaviour:** prompts, keys, output formats and defaults.
- **Files and environment variables** it reads or writes.

Before committing, read the README sections your change touches and fix anything now untrue, including text written before your change. The README isn't a changelog: describe how the CLI works now, not what changed. `every_command_is_in_the_readme` in `src/main.rs` fails if a command is missing from it, but it can't tell whether the description is right. That part is on you.

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

- **Every command that reports information takes `--json`:** reads, writes (the resulting record), `auth status`. Exceptions, which already print machine output or none of their own: `creds` (`--format`), `exec` (its command's output), `auth token` (a bare token), `api` (the API's response) and `-i` modes (interactive; `list --json` is their counterpart).
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
