"""A stand-in for the source.coop API, for recording demos.

Serves the made-up records in fixtures.json under /api/v1, in memory: what a
demo creates, edits or deletes is seen by the commands after it, and gone
when the stub stops. It answers only what the CLI asks, in the API's shapes;
it checks nothing, so it is no substitute for the API in tests.

Outside /api/v1 it is the data proxy, for `aws s3 ls`: a ListObjectsV2 of
fixtures.json's `objects`, signatures unchecked.

    python3 -I docs/recorder/stub.py PORT [FIXTURES]
"""

import copy, json, os, re, secrets, string, sys, uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from xml.sax.saxutils import escape

GITHUB = "https://token.actions.githubusercontent.com"
here = os.path.dirname(os.path.abspath(__file__))
data = json.load(open(sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, "fixtures.json")))
accounts = {a["account_id"]: a for a in data["accounts"]}
products, trusts, memberships = data["products"], data["trusts"], data["memberships"]
connections = data["data_connections"]
keys = data.get("keys", [])
objects = data.get("objects", [])
me = data["whoami"]["account"]["account_id"]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def page(items):
    return {"items": items, "next_cursor": None}


TITLES = {400: "Invalid request", 404: "Not found", 409: "Conflict"}


def error(status, code, message, fields=None):
    """An RFC 9457 problem, as the API answers errors. `fields` maps a body
    field to what's wrong with it, given as a JSON Pointer as the API does."""
    problem = {"type": f"https://source.coop/api/problems/{code}", "title": TITLES.get(status, "Error"),
               "status": status, "detail": message, "code": code}
    if fields:
        problem["errors"] = [{"pointer": f"#/{f}", "detail": d} for f, d in fields.items()]
    return status, problem


def issue(account_id, body):
    """A new API key for `account_id`: its record, with the key shown this once."""
    key = "sck_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    k = {"key_id": str(uuid.uuid4()), "account_id": account_id, "label": body.get("label", ""),
         "hint": key[-6:], "created_at": now(), "created_by": me, "expires_at": body.get("expires_at")}
    keys.append(k)
    return dict(k, key=key)


PUBLIC = ("account_id", "type", "name", "disabled", "metadata_public", "profile_image")


def with_account(p):
    """A product as the API returns it, with its owner's public view."""
    a = accounts.get(p["account_id"], {"account_id": p["account_id"]})
    return dict(p, account={k: a[k] for k in PUBLIC if k in a})


def find_product(account, product):
    return next((p for p in products if (p["account_id"], p["product_id"]) == (account, product)), None)


def handle(method, path, q, body):
    if path == "/whoami":
        return 200, data["whoami"]

    if path == "/products":
        found = [p for p in products if p["visibility"] == "public"]
        if "q" in q:
            found = [p for p in found if q["q"].lower() in json.dumps(p).lower()]
        if q.get("featured") == "true":
            found = [p for p in found if p["featured"]]
        return 200, page([with_account(p) for p in found])
    if r := re.fullmatch(r"/products/([^/]+)", path):
        if method == "POST":
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,}", body.get("product_id") or ""):
                return error(400, "invalid", "The request is invalid",
                             {"product_id": "use lowercase letters, numbers and hyphens"})
            if find_product(r[1], body.get("product_id")):
                return error(409, "conflict", "A product with that ID exists", {"product_id": "is taken"})
            c = body.get("data_connection_id", "demo-s3")
            p = {"account_id": r[1], "product_id": body.get("product_id"), "title": body.get("title", ""),
                 "description": body.get("description", ""), "visibility": body.get("visibility", "public"),
                 "disabled": False, "featured": 0, "created_at": now(), "updated_at": now(),
                 "metadata": {"tags": [], "primary_mirror": c,
                              "mirrors": {c: {"connection_id": c, "prefix": f"{r[1]}/{body.get('product_id')}/", "is_primary": True}}}}
            products.append(p)
            return 201, with_account(p)
        return 200, page([with_account(p) for p in products if p["account_id"] == r[1]])
    if r := re.fullmatch(r"/products/([^/]+)/([^/]+)", path):
        p = find_product(r[1], r[2])
        if not p:
            return error(404, "not_found", f"No product {r[1]}/{r[2]}")
        if method == "PATCH":
            p.update(body, updated_at=now())
        if method == "DELETE":
            products.remove(p)
        return 200, with_account(p)

    if path == "/data-connections":
        return 200, page(connections)

    if r := re.fullmatch(r"/accounts/([^/]+)/service-accounts", path):
        owner = r[1]
        if method == "POST":
            sid = f"{owner}--{body.get('local_id')}"
            if sid in accounts:
                return error(409, "conflict", "That ID is taken", {"local_id": "is taken"})
            a = {"account_id": sid, "type": "service", "name": body.get("name", ""), "owner_account_id": owner,
                 "disabled": False, "flags": [], "metadata_public": {}, "created_at": now(), "updated_at": now()}
            accounts[sid] = a
            trusts.extend({"account_id": sid, "issuer": GITHUB, "subject": s, "created_at": now(), "created_by": me}
                          for s in body.get("github_subjects", []))
            memberships.extend({"membership_id": str(uuid.uuid4()), "account_id": sid, "membership_account_id": owner,
                                "product_id": g["product_id"], "role": g["role"], "state": "member",
                                "state_changed": now()} for g in body.get("grants", []))
            if body.get("key"):
                return 201, dict(a, key=issue(sid, body["key"]))
            return 201, a
        return 200, page([a for a in accounts.values() if a.get("owner_account_id") == owner])
    if r := re.fullmatch(r"/accounts/([^/]+)/trusts", path):
        sid = r[1]
        if method == "POST":
            t = {"account_id": sid, "issuer": GITHUB, "subject": body.get("subject"), "created_at": now(), "created_by": me}
            trusts.append(t)
            return 201, t
        mine = [t for t in trusts if t["account_id"] == sid]
        if method == "DELETE":
            t = next((t for t in mine if (t["issuer"], t["subject"]) == (q.get("issuer"), q.get("subject"))), None)
            if not t:
                return error(404, "not_found", "No such trust")
            trusts.remove(t)
            return 200, t
        return 200, page(mine)
    if r := re.fullmatch(r"/accounts/([^/]+)/keys", path):
        if method == "POST":
            return 201, issue(r[1], body)
        return 200, page([k for k in keys if k["account_id"] == r[1]])
    if r := re.fullmatch(r"/accounts/([^/]+)/keys/([^/]+)", path):
        k = next((k for k in keys if (k["account_id"], k["key_id"]) == (r[1], r[2])), None)
        if not k:
            return error(404, "not_found", "No such key")
        if body.get("revoked"):
            if k.get("revoked_at"):
                return error(409, "conflict", "The key is already revoked")
            k.update(revoked_at=now(), revoked_via="owner", revoked_by=me)
        if "expires_at" in body:
            k["expires_at"] = body["expires_at"]
        return 200, k
    if r := re.fullmatch(r"/accounts/([^/]+)", path):
        a = accounts.get(r[1])
        if not a:
            return error(404, "not_found", f"No account {r[1]}")
        if method == "PATCH":
            a.update(body, updated_at=now())
        if method == "DELETE":
            del accounts[r[1]]
        return 200, a

    if path == "/memberships":
        if method == "POST":
            # An invitation, until the invited account accepts it. A service
            # account is added at once, as the API does.
            service = accounts.get(body.get("account_id"), {}).get("type") == "service"
            m = dict(body, membership_id=str(uuid.uuid4()), state="member" if service else "invited",
                     state_changed=now())
            memberships.append(m)
            return 201, m
        filters = ("account_id", "membership_account_id", "product_id", "state")
        found = [m for m in memberships if all(m.get(f) == q[f] for f in filters if f in q)]
        if "membership_account_id" in q and "product_id" not in q:
            # As the API does: an organization's members, without its products'.
            found = [m for m in found if not m.get("product_id")]
        return 200, page(found)
    if r := re.fullmatch(r"/memberships/([^/]+)", path):
        m = next((m for m in memberships if m["membership_id"] == r[1]), None)
        if not m:
            return error(404, "not_found", "No such membership")
        if method != "PATCH":
            return error(404, "not_found", f"The demo stub has no {method} {path}")
        m.update(body, state_changed=now())
        return 200, m

    if path == "/service-account-keys/revocations":
        return 204, None
    return error(404, "not_found", f"The demo stub has no {method} {path}")


def list_objects(bucket, q):
    """S3's ListObjectsV2 of `objects` in `bucket`, folded at the delimiter."""
    prefix, delim = q.get("prefix", ""), q.get("delimiter", "")
    files, folders = [], []
    for o in objects:
        if o["bucket"] != bucket or not o["key"].startswith(prefix):
            continue
        rest = o["key"][len(prefix):]
        if delim and delim in rest:
            folder = prefix + rest.split(delim)[0] + delim
            if folder not in folders:
                folders.append(folder)
        else:
            files.append(o)
    tag = lambda name, text: f"<{name}>{escape(str(text))}</{name}>"
    body = "".join(
        "<Contents>" + tag("Key", o["key"]) + tag("LastModified", o["last_modified"]) + tag("ETag", '"0"')
        + tag("Size", o["size"]) + tag("StorageClass", "STANDARD") + "</Contents>" for o in files)
    body += "".join("<CommonPrefixes>" + tag("Prefix", f) + "</CommonPrefixes>" for f in folders)
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            + tag("Name", bucket) + tag("Prefix", prefix) + tag("Delimiter", delim)
            + tag("KeyCount", len(files) + len(folders)) + tag("MaxKeys", 1000)
            + tag("IsTruncated", "false") + body + "</ListBucketResult>")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def answer(self, method):
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if not url.path.startswith("/api/v1"):
            raw = list_objects(url.path.strip("/").split("/")[0], q).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        status, out = handle(method, url.path.removeprefix("/api/v1"), q, body)
        raw = b"" if out is None else json.dumps(copy.deepcopy(out)).encode()
        self.send_response(status)
        if out is not None:
            self.send_header("Content-Type", "application/problem+json" if status >= 400 else "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self): self.answer("GET")
    def do_POST(self): self.answer("POST")
    def do_PATCH(self): self.answer("PATCH")
    def do_DELETE(self): self.answer("DELETE")


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
