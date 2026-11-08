"""Update a checkout of the gh-pages branch, which holds every published copy
of the docs site (the Docs workflow runs it on each published release, push
to main and PR):

    python3 docs/site/publish.py PAGES release v0.4.0 --site target/site
    python3 docs/site/publish.py PAGES next --site target/site
    python3 docs/site/publish.py PAGES preview 75 --site target/site
    python3 docs/site/publish.py PAGES remove-preview 75

PAGES/
  index.html          sends visitors to latest/
  versions.json       {"latest": tag, "versions": [tags, newest first], "next": true}, for the version menu
  latest/             a copy of the newest release's docs
  next/               main's docs: the next release, never latest
  v0.4.0/ v0.3.0/ …   each release's docs, kept as published
  pr-preview/pr-75/   an open PR's docs
"""

import argparse, json, os, re, shutil

REDIRECT = """<!doctype html>
<meta charset="utf-8">
<title>source-coop CLI guide</title>
<meta http-equiv="refresh" content="0; url=latest/">
<link rel="canonical" href="latest/">
<a href="latest/">The source-coop CLI guide</a>
"""


def semver(v):
    """A sort key for tags like v0.4.0 and v1.0.0-rc.1 (a pre-release sorts first)."""
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(-.+)?", v)
    if not m:
        raise SystemExit(f"not a version: {v}")
    return (int(m[1]), int(m[2]), int(m[3]), m[4] is None, m[4] or "")


def replace(src, dst):
    if os.path.exists(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("pages", help="the gh-pages checkout")
    p.add_argument("action", choices=["release", "next", "preview", "remove-preview"])
    p.add_argument("name", nargs="?", default="next", help="the release's tag, or the PR's number (not for next)")
    p.add_argument("--site", help="the built site (docs/site/build.py --out)")
    a = p.parse_args()
    if a.action != "remove-preview" and not a.site:
        p.error("--site is needed to publish")

    if a.action in ("release", "preview", "remove-preview") and a.name == "next":
        p.error(f"{a.action} needs a name")
    listed = os.path.join(a.pages, "versions.json")
    known = json.load(open(listed)) if os.path.exists(listed) else {"latest": None, "versions": []}

    if a.action == "release":
        versions = sorted(set(known["versions"]) | {a.name}, key=semver, reverse=True)
        replace(a.site, os.path.join(a.pages, a.name))
        # Pre-releases are published but never become latest.
        stable = [v for v in versions if semver(v)[3]]
        latest = known["latest"]
        if stable and stable[0] == a.name:
            replace(a.site, os.path.join(a.pages, "latest"))
            latest = a.name
        known.update(latest=latest, versions=versions)
    elif a.action == "next":
        replace(a.site, os.path.join(a.pages, "next"))
        known["next"] = True
    elif a.action == "preview":
        replace(a.site, os.path.join(a.pages, "pr-preview", f"pr-{int(a.name)}"))
    else:
        shutil.rmtree(os.path.join(a.pages, "pr-preview", f"pr-{int(a.name)}"), ignore_errors=True)

    with open(listed, "w") as f:
        json.dump(known, f, indent=1)
    with open(os.path.join(a.pages, "index.html"), "w") as f:
        f.write(REDIRECT)
    # Serve folders as they are: nothing here is for Jekyll.
    open(os.path.join(a.pages, ".nojekyll"), "w").close()
    print(f"{a.action} {a.name} in {a.pages}")


if __name__ == "__main__":
    main()
