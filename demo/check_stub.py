"""Check demo/stub.py's answers against the API's OpenAPI spec.

Starts the stub, makes a request to each of its routes, and validates every
answer against the schema the spec gives for that path, method and status.
Exits 1 if any answer doesn't match, or if the stub serves something the spec
doesn't have, so drift between the stub and the API fails a check instead of
showing up in a demo.

    pip install jsonschema    # or: uv run --with jsonschema python demo/check_stub.py
    python3 demo/check_stub.py [SPEC]

SPEC is a URL or a file [https://staging.source.coop/api/openapi].
"""

import json, os, re, socket, subprocess, sys, time, urllib.error, urllib.request

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

STAGING = "https://staging.source.coop/api/openapi"
here = os.path.dirname(os.path.abspath(__file__))


def load_spec(where):
    if re.match(r"https?://", where):
        with urllib.request.urlopen(where) as r:
            return json.load(r)
    with open(where) as f:
        return json.load(f)


def requests(fx):
    """(method, path, body) for each route the stub serves, filled in from the fixtures."""
    product = fx["products"][0]
    service = next(a for a in fx["accounts"] if a["type"] == "service")
    owner = service["owner_account_id"]
    key = next(k for k in fx["keys"] if k["account_id"] == service["account_id"])
    membership = fx["memberships"][0]["membership_id"]
    return [
        ("GET", "/whoami", None),
        ("GET", "/products", None),
        ("GET", "/products?featured=true", None),
        ("GET", f"/products/{owner}", None),
        ("GET", f"/products/{product['account_id']}/{product['product_id']}", None),
        ("GET", "/products/demo-org/no-such-product", None),  # a 404 problem
        ("POST", f"/products/{product['account_id']}", {"product_id": product["product_id"]}),  # a 409 problem
        ("GET", "/data-connections", None),
        ("GET", f"/accounts/{service['account_id']}", None),
        ("GET", f"/accounts/{owner}/service-accounts", None),
        ("GET", f"/accounts/{service['account_id']}/trusts", None),
        ("GET", f"/accounts/{service['account_id']}/keys", None),
        ("PATCH", f"/accounts/{service['account_id']}/keys/{key['key_id']}", {"expires_at": None}),
        ("GET", "/memberships", None),
        ("PATCH", f"/memberships/{membership}", {"role": "maintainers"}),
    ]


def operation(spec, method, path):
    """The spec's path template and operation for a request, or (None, None)."""
    for template, item in spec["paths"].items():
        if re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", template), path.split("?")[0]) and method.lower() in item:
            return template, item[method.lower()]
    return None, None


def pointer(*parts):
    return "/".join(p.replace("~", "~0").replace("/", "~1") for p in parts)


def check(spec, registry, method, path, status, body):
    """What's wrong with one answer, as lines; empty when it matches."""
    template, op = operation(spec, method, path)
    if not op:
        return [f"the spec has no {method} {path}"]
    code = str(status) if str(status) in op["responses"] else "default"
    if code not in op["responses"]:
        return [f"the spec doesn't list {status} for {method} {template}"]
    at, response = pointer("", "paths", template, method.lower(), "responses", code), op["responses"][code]
    while "$ref" in response:
        at = response["$ref"].removeprefix("#")
        response = spec["components"]["responses"][at.rsplit("/", 1)[1]]
    content = response.get("content", {})
    ctype = next((t for t in content if "json" in t), None)
    if body is None or not ctype or "schema" not in content[ctype]:
        return []
    schema = {"$ref": f"urn:spec#{at}/{pointer('content', ctype, 'schema')}"}
    errors = Draft202012Validator(schema, registry=registry).iter_errors(body)
    return [f"/{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}"
            for e in sorted(errors, key=lambda e: list(map(str, e.absolute_path)))]


def main():
    spec = load_spec(sys.argv[1] if len(sys.argv) > 1 else STAGING)
    registry = Registry().with_resource("urn:spec", Resource.from_contents(spec, DRAFT202012))
    with open(os.path.join(here, "fixtures.json")) as f:
        fx = json.load(f)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    stub = subprocess.Popen([sys.executable, "-I", os.path.join(here, "stub.py"), str(port)])
    failed = 0
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), 0.1).close()
                break
            except OSError:
                time.sleep(0.05)
        for method, path, payload in requests(fx):
            data = None if payload is None else json.dumps(payload).encode()
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1{path}", data, method=method,
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req) as r:
                    status, raw = r.status, r.read()
            except urllib.error.HTTPError as e:
                status, raw = e.code, e.read()
            problems = check(spec, registry, method, path, status, json.loads(raw) if raw else None)
            print(f"{'ok  ' if not problems else 'FAIL'}  {method} {path} {status}")
            for p in problems[:5]:
                print(f"        {p}")
            failed += bool(problems)
    finally:
        stub.kill()
        stub.wait()
    if failed:
        sys.exit(f"{failed} of the stub's answers don't match the spec: fix demo/stub.py or demo/fixtures.json")


if __name__ == "__main__":
    main()
