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

# Script first, so the browser leaves before painting; the refresh and the
# styled link are for visitors without JavaScript.
REDIRECT = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>source-coop CLI guide</title>
<script>location.replace("latest/" + location.search + location.hash);</script>
<meta http-equiv="refresh" content="0; url=latest/">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="canonical" href="latest/">
<link rel="icon" href="latest/assets/icon.svg" type="image/svg+xml">
<style>
  :root { color-scheme: light dark; --bg: #EFEBEA; --fg: #121A1B; --muted: #4A5253; }
  @media (prefers-color-scheme: dark) { :root { --bg: #121A1B; --fg: #EFEBEA; --muted: #ABAFAE; } }
  body { margin: 0; min-height: 100vh; display: grid; place-content: center; gap: 16px; padding: 0 16px;
    background: var(--bg); color: var(--fg); font: 16px/1.55 "IBM Plex Sans", system-ui, -apple-system, sans-serif; text-align: center; }
  img { margin: 0 auto; }
  .bone { display: none; }
  @media (prefers-color-scheme: dark) { .ink { display: none; } .bone { display: block; } }
  a { color: inherit; font: 700 15px ui-monospace, SFMono-Regular, Menlo, monospace; }
  p { margin: 0; color: var(--muted); }
</style>
</head>
<body>
<img class="ink" src="latest/assets/logo-ink.svg" alt="Source Cooperative" width="146" height="39">
<img class="bone" src="latest/assets/logo-bone.svg" alt="Source Cooperative" width="146" height="39">
<p>Taking you to the <a href="latest/">source-coop CLI guide</a>…</p>
</body>
</html>
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
