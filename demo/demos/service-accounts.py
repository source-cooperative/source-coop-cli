"""Demos of `source-coop service-account`, against demo/stub.py's fixtures:

    python3 -I demo/record.py demo/demos/service-accounts.py [NAME ...]

DOWN, UP, RIGHT, LEFT, ESC and BACKSPACE are given by record.py. The GitHub
lookups are real: source-cooperative/source.coop is public.
"""

ORG = "demo-org"
REPO = "source-cooperative/source.coop"


def list_accounts(s):
    s.run(f"source-coop service-account list {ORG}")
    s.prompt()
    s.run(f"source-coop service-account list {ORG} --json | jq -c '.[] | {{account_id, name, disabled}}'")


def view(s):
    s.run(f"source-coop service-account view {ORG}--nightly-sync")
    s.prompt()
    s.pause(2)
    s.run(f"source-coop service-account view {ORG}--nightly-sync --json"
          " | jq '{account_id, trusts: [.trusts[].subject], memberships: [.memberships[] | {product_id, role}]}'")


def create(s):
    s.run("source-coop service-account create")
    s.see("Owner"); s.key(DOWN); s.enter()
    s.see("Name"); s.type("Weekly mosaic"); s.enter()
    s.see("ID"); s.pause(1); s.enter()
    s.see("add a sign-in"); s.key(UP, 2); s.enter()
    s.see("Repository"); s.type(REPO); s.enter()
    s.see("Allow runs from"); s.enter()
    s.see("Branch"); s.pause(0.8); s.enter()
    s.see("another"); s.pause(1.2); s.key(UP); s.enter()
    s.see("Label"); s.type("Render farm"); s.enter()
    s.see("Expires"); s.pause(1); s.enter()
    s.see("another"); s.pause(1); s.enter()
    s.see("grant a product"); s.key(UP, 2); s.enter()
    s.see("Access"); s.key(DOWN); s.enter()
    s.see("another"); s.pause(0.8); s.enter()
    s.see("Create this service account"); s.pause(3.5); s.enter()
    s.see("Save the key to a file"); s.type("render-farm.key"); s.enter()
    s.prompt()
    s.run("ls -l render-farm.key | awk '{print $1, $NF}'")


def create_flags(s):
    s.run(f"source-coop service-account create {ORG}--tile-builder --name 'Tile builder' \\")
    s.see("> $")
    s.run(f"  --github {REPO} --tag v1.2.0 --access {ORG}/landsat-mirror=read --json")


def browse(s):
    s.run(f"source-coop service-account list {ORG} -i")
    s.see("Service accounts of"); s.pause(1.2); s.key(DOWN); s.key(RIGHT)
    s.see("Can reach"); s.pause(3); s.key(LEFT)
    s.see("Service accounts of"); s.key(DOWN); s.key(RIGHT)
    s.see("Can reach"); s.pause(1.5); s.key("d")
    s.see("Type"); s.pause(1); s.type(f"{ORG}--old-backfill"); s.enter()
    s.see("Deleted"); s.pause(2.5); s.key("q")
    # The picker leaves the screen as it was; show what's left.
    s.prompt()
    s.run(f"source-coop service-account list {ORG}")


def edit(s):
    s.run(f"source-coop service-account edit {ORG}--stac-indexer --disable"); s.prompt(); s.pause(2)
    s.run(f"source-coop service-account edit {ORG}--stac-indexer --enable"); s.prompt()
    s.run(f"source-coop service-account edit {ORG}--stac-indexer")
    s.see("Name"); s.pause(0.8)
    s.key(BACKSPACE * len("STAC indexer"))
    s.type("STAC indexer (production)"); s.enter()


def delete(s):
    s.run(f"source-coop service-account delete {ORG}--old-backfill")
    s.see("Type"); s.pause(2.5); s.type(f"{ORG}--old-backfill"); s.enter(); s.prompt()
    s.run(f"source-coop service-account delete {ORG}--stac-indexer --yes --json | jq -c '{{account_id, name}}'")


def sign_in(s):
    s.run(f"source-coop service-account sign-in add {ORG}--nightly-sync")
    s.see("Sign in with"); s.pause(1); s.enter()
    s.see("Repository"); s.type(REPO); s.enter()
    s.see("Allow runs from"); s.key(DOWN, 2); s.enter()
    s.see("Environment"); s.type("staging"); s.enter()
    s.see("Trust this workflow"); s.pause(3.5); s.enter(); s.prompt()
    s.run(f"source-coop service-account sign-in add {ORG}--nightly-sync --github {REPO} --tag v2.0.0 --json | jq -c"); s.prompt()
    s.run(f"source-coop service-account sign-in remove {ORG}--nightly-sync -i")
    s.see("Remove which sign-in"); s.key(DOWN, 2); s.enter()
    s.see("signing in as"); s.pause(1.2); s.key("y"); s.prompt()
    # A made-up key, in the shape of a real one.
    s.run("echo sck_0000demo0000demo0000demo0000demoK3yQ > leaked.key"); s.prompt()
    s.run("source-coop service-account sign-in revoke-key < leaked.key")


def keys(s):
    s.run(f"source-coop service-account view {ORG}--nightly-sync | sed -n '/Signs in with/,/^$/p'")
    s.prompt(); s.pause(2.5)
    s.run(f"source-coop service-account sign-in add {ORG}--nightly-sync --key 'Batch server' --expires 30d --out batch.key")
    s.prompt()
    s.run("ls -l batch.key | awk '{print $1, $NF}'")
    s.prompt()
    s.run(f"source-coop service-account sign-in edit {ORG}--nightly-sync -i")
    s.see("Change which key"); s.pause(1); s.enter()
    s.see("When should"); s.key(DOWN); s.enter()
    s.prompt()
    s.run(f"source-coop service-account sign-in remove {ORG}--nightly-sync key:Qx7Lm2")
    s.see("Type"); s.pause(1.5); s.type("key:Qx7Lm2"); s.enter()
    s.prompt()
    s.run(f"source-coop service-account view {ORG}--nightly-sync | sed -n '/Signs in with/,/^$/p'")


def access(s):
    s.run(f"source-coop service-account access set {ORG}--nightly-sync {ORG}/demo-data --role write"); s.prompt()
    s.run(f"source-coop service-account access set {ORG}--nightly-sync {ORG}/demo-data --role read --json | jq -c '{{product_id, role}}'"); s.prompt()
    s.run(f"source-coop service-account access remove {ORG}--nightly-sync -i")
    s.see("Remove access"); s.pause(1.2); s.enter(); s.prompt()
    s.run(f"source-coop service-account view {ORG}--nightly-sync | tail -4")


def usage(s):
    s.run(f"source-coop service-account usage {ORG}--stac-indexer")
    s.see("Sign in with"); s.pause(1.5); s.enter(); s.prompt(); s.pause(3.5)
    s.run(f"clear; source-coop service-account usage {ORG}--stac-indexer --key")


DEMOS = {
    "list": ("`service-account list`: an owner's service accounts, then as `--json`", list_accounts),
    "view": ("`service-account view`: who it is, signs in with, can reach; `--json` adds `trusts` and `memberships`", view),
    "create": ("`service-account create` with prompts: owner, name, ID, a GitHub workflow (checked with GitHub), an API key, a product grant, review, then saving the key", create),
    "create-flags": ("`service-account create` from flags, `--json`", create_flags),
    "picker": ("`service-account list -i`: open a record, go back, delete one from its screen", browse),
    "edit": ("`service-account edit`: `--disable` and `--enable` (with the web UI's explanations), then a rename from the current name", edit),
    "delete": ("`service-account delete`: typed confirmation, then `--yes --json`", delete),
    "sign-in": ("`service-account sign-in add` with prompts (a workflow) and from flags, `sign-in remove -i`, `sign-in revoke-key`", sign_in),
    "keys": ("`service-account view` with API keys, `sign-in add --key --out`, `sign-in edit -i` (a new expiry) and `sign-in remove key:HINT` (revoke, typed back)", keys),
    "access": ("`service-account access set` (grant, then change role) and `access remove -i`", access),
    "usage": ("`service-account usage`: pick a sign-in for its workflow, then `--key`", usage),
}
