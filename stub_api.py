"""A stateful stand-in for source.coop's membership API, for recording demos.

Signed in as `dana`, an owner of `acme-lab`. State resets on restart.
"""
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

NOW = datetime.now(timezone.utc)
ME = "dana"
KNOWN = {"dana", "alice", "bob", "carol", "erin", "frank", "grace", "heidi", "ivan", "judy"}


def ago(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


def m(account, org, role, state, when, product=None):
    row = {
        "membership_id": str(uuid.uuid4()),
        "account_id": account,
        "membership_account_id": org,
        "role": role,
        "state": state,
        "state_changed": when,
    }
    if product:
        row["repository_id"] = product
    return row


ROWS = [
    m("dana", "acme-lab", "owners", "member", ago(days=800)),
    m("alice", "acme-lab", "maintainers", "member", ago(days=400)),
    m("bob", "acme-lab", "read_data", "member", ago(days=90)),
    m("carol", "acme-lab", "write_data", "invited", ago(days=3)),
    m("erin", "acme-lab", "read_data", "member", ago(days=30), "climate-data"),
    m("frank", "acme-lab", "write_data", "invited", ago(hours=5), "climate-data"),
    # dana's own elsewhere
    m("dana", "ocean-watch", "read_data", "member", ago(days=200)),
    m("dana", "geo-commons", "maintainers", "invited", ago(days=1)),
    m("dana", "geo-commons", "read_data", "invited", ago(hours=2), "elevation"),
    m("dana", "river-sensors", "write_data", "invited", ago(days=6)),
]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def err(self, status, code, message, field_errors=None):
        e = {"code": code, "message": message}
        if field_errors:
            e["field_errors"] = field_errors
        self.send(status, {"error": e})

    def parts(self):
        u = urlparse(self.path)
        p = u.path.removeprefix("/api/v1/").strip("/").split("/")
        return p, parse_qs(u.query)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        p, q = self.parts()
        if p == ["whoami"]:
            mine = [r for r in ROWS if r["account_id"] == ME and r["state"] == "member"]
            return self.send(200, {"account": {"account_id": ME, "type": "individual"}, "memberships": mine})
        if p == ["memberships"]:
            state = q.get("state", [None])[0]
            rows = [r for r in ROWS if r["account_id"] == ME and r["state"] != "revoked"]
            if state:
                rows = [r for r in rows if r["state"] == state]
            return self.send(200, rows)
        if len(p) == 3 and p[0] == "accounts" and p[2] == "members":
            # Like the real API: product-scoped rows come back too.
            return self.send(200, [r for r in ROWS if r["membership_account_id"] == p[1] and r["state"] != "revoked"])
        if len(p) == 4 and p[0] == "products" and p[3] == "members":
            return self.send(200, [r for r in ROWS if r["membership_account_id"] == p[1]
                                   and r.get("repository_id") == p[2] and r["state"] != "revoked"])
        self.err(404, "not_found", "Not found")

    def do_POST(self):
        p, _ = self.parts()
        if p and p[0] in ("accounts", "products") and p[-1] == "members":
            b = self.body()
            org, product = p[1], (p[2] if p[0] == "products" else None)
            acct, role = b.get("account_id", ""), b.get("role", "")
            if role not in ("owners", "maintainers", "write_data", "read_data"):
                return self.err(400, "validation_error", "Invalid request", {"role": ["Invalid role"]})
            if acct not in KNOWN:
                return self.err(404, "not_found", f"Account {acct} not found")
            if any(r["account_id"] == acct and r["membership_account_id"] == org
                   and r.get("repository_id") == product and r["state"] != "revoked" for r in ROWS):
                return self.err(409, "conflict", f"{acct} already has a membership here")
            row = m(acct, org, role, "invited", ago(seconds=0), product)
            ROWS.append(row)
            return self.send(201, row)
        if len(p) == 3 and p[0] == "memberships":
            row = next((r for r in ROWS if r["membership_id"] == p[1]), None)
            if not row:
                return self.err(404, "not_found", "Membership not found")
            row["state"] = {"accept": "member", "reject": "revoked", "revoke": "revoked"}[p[2]]
            row["state_changed"] = ago(seconds=0)
            return self.send(200, row)
        self.err(404, "not_found", "Not found")

    def do_PATCH(self):
        p, _ = self.parts()
        row = next((r for r in ROWS if len(p) == 2 and r["membership_id"] == p[1]), None)
        if not row:
            return self.err(404, "not_found", "Membership not found")
        row["role"] = self.body().get("role", row["role"])
        return self.send(200, row)


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
