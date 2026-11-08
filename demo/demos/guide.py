"""The demos the README shows, against demo/stub.py's fixtures. Recorded into
docs/demos/, which the README embeds and git keeps:

    cargo build
    python3 -I demo/record.py demo/demos/guide.py --out docs/demos [NAME ...]

The service-account section's demos come from demo/demos/service-accounts.py,
recorded into docs/demos/service-account/. DOWN, UP, RIGHT, LEFT, ESC and
BACKSPACE are given by record.py.
"""

ORG = "demo-org"


def product_list(s):
    s.run(f"source-coop product list {ORG} --format table"); s.prompt(); s.pause(1.5)
    s.run("source-coop product list -q ocean"); s.prompt(); s.pause(2)
    s.run(f"source-coop product list {ORG} --json | jq -c '.[] | {{product_id, visibility}}'")


def product_browse(s):
    s.run(f"source-coop product list {ORG} -i")
    s.see("Landsat"); s.pause(1.2); s.key(DOWN); s.key(DOWN); s.key(RIGHT)
    s.see("Cloud-optimized"); s.pause(2.5); s.key(LEFT)
    s.see("Landsat"); s.pause(0.8); s.key("/"); s.type("clim"); s.pause(1.5); s.enter()
    s.pause(1); s.key(RIGHT)
    s.see("Daily gridded"); s.pause(2.5); s.key(LEFT); s.pause(1); s.key("q")


def product_create(s):
    s.run("source-coop product create")
    s.see("Account"); s.key(DOWN); s.enter()
    s.see("Product ID"); s.type("sea-ice"); s.enter()
    s.see("Title"); s.pause(1.2)
    s.key(UP)  # back to the product ID, which keeps its answer
    s.see("Product ID"); s.pause(1); s.type("-extent"); s.enter()
    s.see("Title"); s.pause(1); s.enter()
    s.see("Description"); s.type("Daily Arctic sea-ice extent from passive microwave."); s.enter()
    s.see("Data connection"); s.pause(1); s.enter()
    s.see("Visibility"); s.pause(1); s.key(DOWN); s.enter()
    s.see("Create this product"); s.pause(3.5); s.enter()
    s.prompt()
    s.run(f"source-coop product view {ORG}/sea-ice-extent --json | jq -c '{{product_id, title, visibility}}'")


def product_edit(s):
    s.run(f"source-coop product edit {ORG}/demo-data")
    s.see("Save changes"); s.pause(1.2); s.enter()   # Title
    s.see("Title"); s.pause(0.6); s.type(" (2026)"); s.enter()
    s.see("Save changes"); s.pause(0.8); s.key(DOWN, 2); s.enter()   # Visibility
    s.see("Visibility"); s.pause(1); s.key(UP); s.enter()
    s.see("Save changes"); s.pause(1.5); s.key("s")
    s.see("Save these changes"); s.pause(3); s.enter()
    s.prompt()
    s.run(f"source-coop product edit {ORG}/demo-data --visibility unlisted --json | jq -c '{{title, visibility}}'")


def product_delete(s):
    s.run(f"source-coop product delete {ORG}/demo-data")
    s.see("Keep the product's data"); s.pause(1.5); s.enter()
    s.see("Type"); s.pause(1.5); s.type(f"{ORG}/demo-dat"); s.enter()
    s.prompt(); s.pause(1.5)
    s.run(f"source-coop product delete {ORG}/demo-data")
    s.see("Keep the product's data"); s.pause(1); s.enter()
    s.see("Type"); s.pause(1); s.type(f"{ORG}/demo-data"); s.enter()
    s.prompt(); s.pause(1.5)
    s.run(f"source-coop product delete {ORG}/landsat-mirror --yes --preserve-data --json | jq -c '{{product_id}}'")


def members(s):
    s.run(f"source-coop member list {ORG}"); s.prompt(); s.pause(1.5)
    s.run(f"source-coop member invite {ORG}")
    s.see("Account IDs"); s.type("alan-demo katherine-demo"); s.enter()
    s.see("Role"); s.pause(1); s.key(UP); s.enter()
    s.see("Invite"); s.pause(2.5); s.enter()
    s.prompt()
    s.run(f"source-coop member edit {ORG} grace-demo")
    s.see("Role for"); s.pause(1); s.key(UP); s.enter()
    s.prompt()
    s.run(f"source-coop member revoke {ORG} linus-demo")
    s.see(r"\?"); s.pause(1.5); s.key("y")


def member_browse(s):
    s.run(f"source-coop member list {ORG} -i")
    s.see("grace-demo"); s.pause(1.2); s.key(DOWN, 3); s.key(RIGHT)
    s.see("Role"); s.pause(1.5); s.key("e")
    s.see("Role for"); s.pause(1); s.key(UP); s.enter()
    s.pause(2.5); s.key(LEFT); s.pause(1); s.key("q")


def invitations(s):
    s.run("source-coop invitation list"); s.prompt(); s.pause(1.5)
    s.run("source-coop invitation list -i")
    s.see("ocean-buoys"); s.pause(1.2); s.key(RIGHT)
    s.see("Role"); s.pause(1.5); s.key("a")
    s.see("Accepted"); s.pause(2.5); s.key(LEFT)  # quits: the list is the top
    s.prompt()
    s.run("source-coop invitation reject partner-org/ocean-buoys --json | jq -c '{membership_account_id, product_id, state}'")


def scripting(s):
    s.run(f"source-coop product view {ORG}/missing; echo \"exit $?\""); s.prompt(); s.pause(1.2)
    s.run(f"source-coop product view {ORG}/missing --json; echo \"exit $?\""); s.prompt(); s.pause(1.2)
    s.run(f"source-coop product create {ORG}/climate-grid -t Copy --json < /dev/null; echo \"exit $?\"")
    s.prompt(); s.pause(1.2)
    s.run(f"source-coop product delete {ORG}/demo-data < /dev/null; echo \"exit $?\""); s.prompt(); s.pause(1.2)
    s.run(f"echo '{{\"title\": \"Buoy archive\", \"visibility\": \"public\"}}' | source-coop product create {ORG}/buoys -F - --data-connection demo-s3")


def api(s):
    s.run(f"source-coop api products/{ORG} | jq -c '.items[] | {{product_id, title}}'"); s.prompt(); s.pause(1.5)
    s.run(f"source-coop api products/{ORG}/demo-data -X PATCH -f title='Demo Data v2' | jq -c '{{product_id, title}}'"); s.prompt(); s.pause(1.5)
    s.run(f"source-coop api products/{ORG}/missing; echo \"exit $?\"")


DEMOS = {
    "product-list": ("`product list`: a table, a search, then `--json`", product_list),
    "product-browse": ("`product list -i`: open a product, go back, filter with `/`", product_browse),
    "product-create": ("`product create` with prompts: ↑ goes back a question, then the review", product_create),
    "product-edit": ("`product edit`: the edit form, then a flag", product_edit),
    "product-delete": ("`product delete`: the name typed wrong, then right, then `--yes`", product_delete),
    "members": ("`member list`, `invite`, `edit` and `revoke`", members),
    "member-browse": ("`member list -i`: open a member and change their role", member_browse),
    "invitations": ("`invitation list -i`: accept one, then reject another", invitations),
    "scripting": ("Errors, `--json` and exit codes, without a terminal, and `-F -`", scripting),
    "api": ("`api`: any request to the API", api),
}
