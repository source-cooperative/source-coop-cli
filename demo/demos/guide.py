"""The demos the README shows, against demo/stub.py's fixtures. Recorded into
docs/demos/, which the README embeds and git keeps:

    cargo build
    python3 -I demo/record.py demo/demos/guide.py --out docs/demos [NAME ...]

The service-account section's demos come from demo/demos/service-accounts.py,
recorded into docs/demos/ too. DOWN, UP, RIGHT, LEFT, ESC and
BACKSPACE are given by record.py.
"""

import base64, json, os, sys, time
from urllib.parse import urlparse

ORG = "demo-org"


def jwt(**claims):
    """A made-up, unsigned JWT: the CLI reads only its `exp`."""
    part = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{part({'alg': 'none'})}.{part(claims)}.demo"


def signed_in(s):
    """Write a made-up session and role credentials into the run's HOME, as
    `auth login` would have, so sign-in demos need no browser or keyring: the
    keyring has nothing for the stub's environment, so the CLI reads these
    files. Everything is fresh, so commands only read them."""
    url, now = urlparse(s.stub_url), int(time.time())
    cache = "Library/Caches" if sys.platform == "darwin" else ".cache"
    env = os.path.join(s.home, cache, "source-coop", "env", url.hostname, str(url.port))
    os.makedirs(os.path.join(env, "credentials"))
    session = {"proxy_url": s.stub_url, "client_id": "demo-client", "token_endpoint": f"{s.stub_url}/oauth2/token",
               "audience": s.stub_url, "refresh_token": "demo-refresh-token",
               "id_token": jwt(sub="demo-user", exp=now + 3600),
               "access_token": jwt(sub="demo-user", aud=s.stub_url, exp=now + 3600),
               "access_token_expires_at": now + 3600, "account": {"account_id": "demo-user", "name": "Demo User"},
               "refresh_token_issued_at": now - 3 * 3600}
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 5400))
    creds = {"access_key_id": "ASIADEMOEXAMPLE00001", "secret_access_key": "demo/secret/not-a-real-key",
             "session_token": "demo-session-token", "expiration": expires, "sts": {"proxy_url": s.stub_url}}
    for path, value in ((os.path.join(env, "session.json"), session),
                        (os.path.join(env, "credentials", "_default.json"), creds)):
        with open(path, "w") as f:
            json.dump(value, f)
    os.makedirs(os.path.join(s.home, ".aws"))
    with open(os.path.join(s.home, ".aws", "config"), "w") as f:
        f.write(f"[profile source-coop]\ncredential_process = source-coop creds\nendpoint_url = {s.stub_url}\n")


def tour(s):
    s.run(f"source-coop product list {ORG} --format table"); s.prompt(); s.pause(1.5)
    s.run(f"source-coop product view {ORG}/demo-data"); s.prompt(); s.pause(2)
    s.run(f"source-coop product view {ORG}/demo-data --json | jq -c '{{product_id, title, visibility}}'")


def auth_status(s):
    signed_in(s)
    s.run("source-coop auth status"); s.prompt(); s.pause(3)
    s.run("source-coop auth status --json | jq -c '.login | {state, account: .account.account_id}'")


def auth_token(s):
    signed_in(s)
    s.run('curl -s -H "Authorization: Bearer $(source-coop auth token)" \\')
    s.see(">"); s.type("  $SOURCE_API_URL/api/v1/whoami | jq -c '.account | {account_id, name}'", 0.2); s.enter()


def auth_logout(s):
    signed_in(s)
    s.run("source-coop auth logout --json | jq -c"); s.prompt(); s.pause(1.5)
    s.run("source-coop auth status"); s.prompt(); s.pause(1.5)
    s.run("source-coop creds; echo \"exit $?\"")


def aws(s):
    signed_in(s)
    s.run("cat ~/.aws/config"); s.prompt(); s.pause(2)
    s.run(f"aws s3 ls s3://{ORG}/demo-data/ --profile source-coop"); s.prompt(); s.pause(1.5)
    s.run(f"aws s3 ls s3://{ORG}/demo-data/readings/ --profile source-coop --human-readable"); s.prompt(); s.pause(1.5)
    s.run("source-coop creds --format env")


def prompts(s):
    s.run("source-coop product create")
    s.see("Account"); s.key(DOWN); s.enter()
    s.see("Product ID"); s.type("Sea Ice"); s.enter()
    s.see("Title"); s.pause(0.8); s.type("Sea Ice"); s.enter()
    s.see("Description"); s.pause(0.6); s.enter()
    s.see("Data connection"); s.pause(0.8); s.enter()
    s.see("Visibility"); s.pause(0.8); s.enter()
    s.see("Create this product"); s.pause(1.5); s.enter()
    # A 400 naming a field: asked again for just that one.
    s.see("Product ID", step="The API refused the ID, so it's asked again"); s.pause(2.5)
    s.key(BACKSPACE, 7); s.type("sea-ice"); s.enter()
    s.prompt(); s.pause(2)
    # Any other failure, here a 409, keeps the answers as a draft.
    s.run(f"clear; source-coop product create {ORG}/climate-grid")
    s.see("Title"); s.pause(0.8); s.enter()
    s.see("Description"); s.pause(0.6); s.enter()
    s.see("Data connection"); s.pause(0.8); s.enter()
    s.see("Visibility"); s.pause(0.8); s.enter()
    s.see("Create this product"); s.pause(1); s.enter()
    s.prompt(); s.pause(3)
    s.run("clear; source-coop product create")
    s.see("Account"); s.pause(1.5); s.key(ESC)
    s.prompt(); s.run('echo "exit $?"')


def completion(s):
    s.run('eval "$(source-coop completions bash)"'); s.prompt()
    s.type("source-coop product view demo-org/", 0.7); s.pause(0.5); s.key("\t", 2)
    s.pause(2.5); s.type("cl"); s.key("\t"); s.pause(1.5); s.enter()
    s.prompt(); s.pause(1)
    s.type("source-coop service-account view demo", 0.7); s.pause(0.5); s.key("\t"); s.pause(0.8); s.key("\t", 2)
    s.pause(2.5); s.key("\x03")   # Ctrl+C: leave the line unrun


def product_list(s):
    s.run(f"source-coop product list {ORG} --format table"); s.prompt(); s.pause(1.5)
    s.run("source-coop product list -q ocean"); s.prompt(); s.pause(2)
    s.run(f"source-coop product list {ORG} --json | jq -c '.[] | {{product_id, visibility}}'")


def product_browse(s):
    s.run(f"source-coop product list {ORG} -i")
    s.see("Landsat", step="The list"); s.pause(1.2); s.key(DOWN); s.key(DOWN); s.key(RIGHT)
    s.see("Cloud-optimized", step="Landsat Mirror"); s.pause(2.5); s.key(LEFT)
    s.see("Landsat", step="Back to the list, then filter"); s.pause(0.8); s.key("/"); s.type("clim"); s.pause(1.5); s.enter()
    s.pause(1); s.key(RIGHT)
    s.see("Daily gridded", step="Climate Grid"); s.pause(2.5); s.key(LEFT); s.pause(1); s.key("q")


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
    s.see("Save changes", step="The edit form"); s.pause(1.2); s.enter()   # Title
    s.see("Title"); s.pause(0.6); s.type(" (2026)"); s.enter()
    s.see("Save changes", step="Title changed"); s.pause(0.8); s.key(DOWN, 2); s.enter()   # Visibility
    s.see("Visibility"); s.pause(1); s.key(UP); s.enter()
    s.see("Save changes", step="Visibility changed"); s.pause(1.5); s.key("s")
    s.see("Save these changes"); s.pause(3); s.enter()
    s.prompt()
    s.run(f"source-coop product edit {ORG}/demo-data --visibility unlisted --json | jq -c '{{title, visibility}}'")


def product_delete(s):
    s.run(f"source-coop product delete {ORG}/demo-data")
    s.see("Keep the product's data"); s.pause(1.5); s.enter()
    s.see("Type", step="Type the name to confirm"); s.pause(1.5); s.type(f"{ORG}/demo-dat"); s.enter()
    s.prompt(); s.pause(1.5)
    s.run(f"source-coop product delete {ORG}/demo-data")
    s.see("Keep the product's data"); s.pause(1); s.enter()
    s.see("Type", step="Type the name to confirm"); s.pause(1); s.type(f"{ORG}/demo-data"); s.enter()
    s.prompt(); s.pause(1.5)
    s.run(f"source-coop product delete {ORG}/landsat-mirror --yes --preserve-data --json | jq -c '{{product_id}}'")


def member_list(s):
    s.run(f"source-coop member list {ORG}"); s.prompt(); s.pause(1.5)
    s.run(f"source-coop member view {ORG} grace-demo"); s.prompt(); s.pause(1.5)
    s.run(f"source-coop member list {ORG} --json | jq -c '.[] | {{account_id, role, state}}'")


def member_invite(s):
    s.run(f"source-coop member invite {ORG}")
    s.see("Account IDs"); s.type("alan-demo katherine-demo"); s.enter()
    s.see("Role"); s.pause(1); s.key(UP); s.enter()
    s.see("Invite"); s.pause(2.5); s.enter()
    s.prompt()
    s.run(f"source-coop member invite {ORG}/demo-data ada-demo --role read_data --json | jq -c '.[] | {{account_id, role, state}}'")


def member_edit(s):
    s.run(f"source-coop member edit {ORG} grace-demo")
    s.see("Role for"); s.pause(1); s.key(UP); s.enter()
    s.prompt(); s.pause(1)
    s.run(f"source-coop member edit {ORG} grace-demo --role read_data --json | jq -c '{{account_id, role}}'")


def member_revoke(s):
    s.run(f"source-coop member revoke {ORG} linus-demo")
    s.see(r"\?", step="Withdraw linus-demo's invitation?"); s.pause(1.5); s.key("y")
    s.prompt(); s.pause(1)
    s.run(f"source-coop member leave {ORG}")
    s.see("Type", step="Type the name to confirm"); s.pause(1.5); s.type("demo-or"); s.enter()
    s.prompt(); s.run('echo "exit $?"')


def member_browse(s):
    s.run(f"source-coop member list {ORG} -i")
    s.see("grace-demo", step="The members"); s.pause(1.2); s.key(DOWN, 3); s.key(RIGHT)
    s.see("Role", step="grace-demo"); s.pause(1.5); s.key("e")
    s.see("Role for"); s.pause(1); s.key(UP); s.enter()
    s.pause(2.5); s.key(LEFT); s.pause(1); s.key("q")


def invitations(s):
    s.run("source-coop invitation list"); s.prompt(); s.pause(1.5)
    s.run("source-coop invitation list -i")
    s.see("ocean-buoys", step="Your invitations"); s.pause(1.2); s.key(RIGHT)
    s.see("Role", step="The invitation to partner-org"); s.pause(1.5); s.key("a")
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
    "tour": ("`source-coop`: an account's products, one product, then as `--json`", tour),
    "auth-status": ("`auth status`, then `--json`", auth_status),
    "auth-token": ("`auth token`: the session's access token, for `curl`", auth_token),
    "auth-logout": ("`auth logout --json`, then `auth status` and `creds` signed out", auth_logout),
    "aws": ("`aws s3 ls` through `credential_process`, then `creds --format env`", aws),
    "prompts": ("Prompts: a refused ID asked again, a draft kept after a failure, then Esc", prompts),
    "completion": ("Shell completion: TAB lists products and service accounts from the API", completion),
    "product-list": ("`product list`: a table, a search, then `--json`", product_list),
    "product-browse": ("`product list -i`: open a product, go back, filter with `/`", product_browse),
    "product-create": ("`product create` with prompts: ↑ goes back a question, then the review", product_create),
    "product-edit": ("`product edit`: the edit form, then a flag", product_edit),
    "product-delete": ("`product delete`: the name typed wrong, then right, then `--yes`", product_delete),
    "member-list": ("`member list` and `view`, then `--json`", member_list),
    "member-invite": ("`member invite` with prompts, then from flags with `--json`", member_invite),
    "member-edit": ("`member edit`: pick a role, then `--role` with `--json`", member_edit),
    "member-revoke": ("`member revoke` an invitation, then `member leave` with the name typed wrong", member_revoke),
    "member-browse": ("`member list -i`: open a member and change their role", member_browse),
    "invitations": ("`invitation list -i`: accept one, then reject another", invitations),
    "scripting": ("Without a terminal: errors, `--json`, exit codes and `-F -`", scripting),
    "api": ("`api`: any request to the API", api),
}
