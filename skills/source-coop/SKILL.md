---
name: source-coop
description: Manage Source Cooperative (source.coop) with the source-coop CLI — accounts, products, members, invitations, service accounts and any API request — and read or write product data with S3 tools. Use when the user mentions Source Cooperative, source.coop or data.source.coop.
---

# source-coop

`source-coop` is the command line for Source Cooperative. Its help is the reference, and it matches the installed version: run `source-coop --help` first, then `source-coop <command> --help` for a command's flags and examples. Don't guess flags. If the command is missing, point the user to <https://cli.source.coop/latest/install/>.

## Using it

- **Start with `source-coop auth status --json`.** If it says you're not signed in, ask the user to sign in themselves: in Claude Code, `! source-coop auth login`; elsewhere, in their own terminal. It opens a browser, so never run it yourself. A script or CI job can set `SOURCE_TOKEN` instead.
- **Pass `--json` to every command that takes it** and parse stdout. Errors are JSON on stderr. Exit codes: 3 means the API refused the input (fix the fields in `field_errors` and retry), 4 not signed in or not allowed, 5 not found.
- **Send bodies with `-F -`** (JSON on stdin), as the help examples do.
- **Never use `-i`.** It opens a full-screen browser for people at a terminal.
- **Ask the user before deleting, revoking or leaving anything**, then pass `--yes`.
- **Anything without a command:** `source-coop api` sends any request to the API. `source-coop --help` says where the OpenAPI spec is.

## Data

A product's files are at `s3://ACCOUNT/PRODUCT/` on the data proxy, `https://data.source.coop`. Public data needs no sign-in. Each tool's settings (AWS CLI, DuckDB, GDAL, Python) are at <https://docs.source.coop/data-proxy>; fetch it rather than guessing. For credentials to private data or for uploads, see the credential commands in `source-coop --help` (`creds`, and `exec` where installed).

## Other tools

To publish a geospatial dataset with its metadata (STAC, GeoParquet, COGs), the Portolan CLI may serve better, if it is installed. `source-coop` handles the accounts, products, members and credentials around it.
