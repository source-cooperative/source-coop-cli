"""Build the docs site from README.md: one page for each `##` section.

    uv run --with markdown-it-py python docs/site/build.py --out target/site [--version v0.4.0]

The README stays the one source. This splits it at its `##` headings, gives
headings the anchors GitHub gives them, points `#anchor` links at the page
that holds the anchor, and turns each demo image (`docs/demos/*.svg`) into
the player in assets/player.js. The site has relative links throughout, so
it works from any folder: a version's, `latest/`, or a PR preview's.
"""

import argparse, html, json, os, re, shutil
from markdown_it import MarkdownIt

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = "https://github.com/source-cooperative/source-coop-cli"
md = MarkdownIt("commonmark", {"html": True}).enable("table")


def slug(text, seen):
    """GitHub's heading anchor for `text`, unique across the README."""
    s = re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")
    n, out = seen.get(s, 0), s
    if n:
        out = f"{s}-{n}"
    seen[s] = n + 1
    return out


def plain(inline):
    """A heading's text as GitHub slugs it: its markdown without the marks."""
    return re.sub(r"[`*_]|\[([^\]]*)\]\([^)]*\)", lambda m: m[1] or "", inline)


GROUP = re.compile(r"^<!-- group: (.+) -->$")


def split(readme):
    """The README's sections: (heading or None for the intro, markdown, group).
    A `<!-- group: NAME -->` line starts a group: the sections after it, up to
    the next, are listed under NAME in the sidebar. GitHub doesn't show it."""
    sections, current, lines, fence, group, starts = [], None, [], False, None, None
    for line in readme.splitlines():
        if line.startswith("```"):
            fence = not fence
        if not fence and GROUP.match(line):
            starts = GROUP.match(line)[1]
            if current is None and not sections and not "".join(lines).strip():
                group, starts = starts, None    # the intro's own group
            continue
        if not fence and line.startswith("## "):
            sections.append((current, "\n".join(lines), group))
            current, lines = line[3:].strip(), []
            if starts:
                group, starts = starts, None
        else:
            lines.append(line)
    sections.append((current, "\n".join(lines), group))
    return sections


def demo_figures(text):
    """Each demo image becomes a figure for the player; the image stays inside
    it for readers without JavaScript."""
    def figure(m):
        alt, path = m[1], m[2]
        caption = md.renderInline(alt)
        return (f'<figure class="demo" data-demo="{html.escape(path)}">'
                f'<noscript><img src="{{root}}demos/{html.escape(path)}.svg" alt="{html.escape(plain(alt))}"></noscript>'
                f'<figcaption>{caption}</figcaption></figure>')
    return re.sub(r"^!\[(.*)\]\(docs/demos/(.+)\.svg\)$", figure, text, flags=re.M)


CALLOUT = re.compile(r"<blockquote>\s*<p>\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*")


def render(text, anchors, page, ids):
    """A section's HTML, with heading ids and links pointed at their pages."""
    tokens = md.parse(text)
    for i, t in enumerate(tokens):
        if t.type == "heading_open":
            t.attrSet("id", ids.pop(0))
        for c in (t.children or []):
            if c.type == "link_open":
                href = c.attrGet("href") or ""
                if re.match(r"^[\w./-]+\.md(#.*)?$", href):
                    # A file in the repository, as GitHub shows it.
                    c.attrSet("href", f"{REPO}/blob/main/{href}")
                elif href.startswith("#") and anchors.get(href[1:]) not in (None, page):
                    target = anchors[href[1:]]
                    c.attrSet("href", "{root}" + (f"{target}/" if target else "") + (href if href[1:] != target else ""))
    out = md.renderer.render(tokens, md.options, {})
    out = CALLOUT.sub(lambda m: f'<blockquote class="callout callout-{m[1].lower()}"><p class="callout-title">{m[1].title()}</p><p>', out)
    return re.sub(r"(<table>.*?</table>)", r'<div class="table-wrap">\1</div>', out, flags=re.S)


def search_entries(body, page, section):
    """The search index for a page: one entry for each heading, with the text
    under it up to the next heading. Demos and the pager aren't text to find."""
    body = re.sub(r"<figure.*?</figure>", "", body, flags=re.S)
    parts = re.split(r'<h[1-4] id="([^"]+)">(.*?)</h[1-4]>', body)
    text = lambda h: " ".join(html.unescape(re.sub(r"<[^>]+>", " ", h)).split())
    return [{"page": page, "id": parts[i], "title": text(parts[i + 1]), "section": section, "text": text(parts[i + 2])}
            for i in range(1, len(parts) - 1, 3)]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--readme", default="README.md")
    p.add_argument("--demos", default="docs/demos")
    p.add_argument("--out", default="target/site")
    p.add_argument("--version", default="dev", help="the version these docs are for: a tag, or e.g. pr-75")
    p.add_argument("--base", default="/source-coop-cli/", help="the site's path on its host, where versions.json is")
    args = p.parse_args()

    sections = split(demo_figures(open(args.readme).read()))
    # Every heading's anchor, and the page that holds it, as GitHub numbers them.
    seen, anchors, ids, pages = {}, {}, [], []
    for heading, text, group in sections:
        name = slug(plain(heading), seen) if heading else ""
        if heading:
            anchors[name] = name
        mine, subs = ([name] if heading else []), []
        for level, h in re.findall(r"^(#{1,6}) (.+)$", re.sub(r"```.*?```", "", text, flags=re.S), re.M):
            a = slug(plain(h), seen)
            anchors[a] = name
            mine.append(a)
            if level == "###":
                subs.append((h, a))
        pages.append({"slug": name, "heading": heading, "text": text, "ids": mine, "subs": subs, "group": group})

    template = open(os.path.join(HERE, "page.html")).read()
    index = []
    if os.path.exists(args.out):
        shutil.rmtree(args.out)
    for i, page in enumerate(pages):
        root = "../" if page["slug"] else ""
        heading_md = f"## {page['heading']}\n" if page["heading"] else ""
        body = render(heading_md + page["text"], anchors, page["slug"], list(page["ids"]))
        if page["heading"]:
            body = body.replace("<h2", "<h1", 1).replace("</h2>", "</h1>", 1)
        index += search_entries(body, page["slug"], plain(page["heading"]) if page["heading"] else "Overview")
        nav, shown_group = [], None
        for q in pages:
            if q["group"] and q["group"] != shown_group:
                nav.append(f'<li class="group">{html.escape(q["group"])}</li>')
                shown_group = q["group"]
            title = md.renderInline(q["heading"]) if q["heading"] else "Overview"
            current = ' aria-current="page"' if q is page else ""
            nav.append(f'<li><a href="{root}{q["slug"] + "/" if q["slug"] else ""}"{current}>{title}</a>')
            if q is page and q["subs"]:
                nav.append("<ul>" + "".join(f'<li><a href="#{a}">{md.renderInline(h)}</a></li>' for h, a in q["subs"]) + "</ul>")
            nav.append("</li>")
        def link(q, rel):
            if not q:
                return "<span></span>"
            title = md.renderInline(q["heading"]) if q["heading"] else "Overview"
            return f'<a class="pager-{rel}" href="{root}{q["slug"] + "/" if q["slug"] else ""}" rel="{rel}"><span>{"Previous" if rel == "prev" else "Next"}</span>{title}</a>'
        pager = link(pages[i - 1] if i else None, "prev") + link(pages[i + 1] if i + 1 < len(pages) else None, "next")
        title = plain(page["heading"]) + " · source-coop CLI" if page["heading"] else "source-coop CLI guide"
        # The body goes in last: the README's own text can hold "{port}" and the like.
        out = (template.replace("{title}", html.escape(title))
               .replace("{nav}", "".join(nav)).replace("{pager}", pager)
               .replace("{version}", html.escape(args.version)).replace("{base}", html.escape(args.base))
               .replace("{page}", page["slug"] + "/" if page["slug"] else "")
               .replace("{repo}", REPO).replace("{root}", root)
               .replace("{body}", body.replace("{root}", root)))
        path = os.path.join(args.out, page["slug"], "index.html")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write(out)

    json.dump(index, open(os.path.join(args.out, "search.json"), "w"), ensure_ascii=False, separators=(",", ":"))
    shutil.copytree(os.path.join(HERE, "assets"), os.path.join(args.out, "assets"))
    shutil.copytree(args.demos, os.path.join(args.out, "demos"))
    print(f"built {len(pages)} pages for {args.version} in {args.out}")


if __name__ == "__main__":
    main()
