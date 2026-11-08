// The theme toggle, the version menu, and the notice on an older version's docs.
(function () {
  var root = document.documentElement;
  var meta = function (name) { var m = document.querySelector('meta[name="' + name + '"]'); return m ? m.content : ""; };

  // Theme: the page loads in this tab's choice or the system's (see page.html).
  // The toggle switches it, and the choice holds for this tab's later pages.
  var theme = document.querySelector(".theme");
  function showTheme() {
    var dark = root.dataset.theme === "dark";
    theme.setAttribute("aria-pressed", String(dark));
    theme.title = dark ? "Switch to light" : "Switch to dark";
  }
  theme.addEventListener("click", function () {
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
    try { sessionStorage.setItem("theme", root.dataset.theme); } catch (e) {}
    showTheme();
  });
  showTheme();

  // On a phone, the contents start folded.
  if (matchMedia("(max-width: 860px)").matches) {
    var toc = document.querySelector(".toc details");
    if (toc) toc.open = false;
  }

  // Versions: versions.json at the site's base names the release in latest/
  // and lists every release, newest first. The button shows this page's
  // version and opens the list; a build that isn't a release (a PR preview, a
  // local build) shows as itself.
  var version = meta("docs-version"), base = meta("docs-base"), page = meta("docs-page");
  var button = document.querySelector(".version-button"), menu = document.getElementById("versions");
  var preview = version.indexOf("pr-") === 0;
  if (preview) button.querySelector(".version-name").textContent = "PR #" + version.slice(3);
  function show(open) {
    menu.hidden = !open;
    button.setAttribute("aria-expanded", String(open));
  }
  button.addEventListener("click", function () { show(menu.hidden); });
  document.addEventListener("click", function (e) { if (!menu.hidden && !e.target.closest(".version")) show(false); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !menu.hidden) { show(false); button.focus(); }
  });
  fetch(base + "versions.json").then(function (r) { return r.ok ? r.json() : Promise.reject(); }).then(function (listed) {
    var versions = listed.versions || [], newest = listed.latest;
    if (!versions.length || !newest) return;
    var item = function (href, name, current, note) {
      var a = document.createElement("a");
      a.href = href;
      a.innerHTML = '<span class="tick" aria-hidden="true"></span><span></span>';
      a.lastChild.textContent = name;
      if (current) { a.setAttribute("aria-current", "page"); a.firstChild.textContent = "✓"; }
      if (note) { var n = document.createElement("span"); n.className = "note"; n.textContent = note; a.appendChild(n); }
      menu.appendChild(a);
    };
    if (preview) item(location.pathname + location.hash, "PR #" + version.slice(3), true, "preview");
    versions.forEach(function (v) {
      item(base + (v === newest ? "latest" : v) + "/" + page, v, v === version, v === newest ? "latest" : "");
    });
    menu.appendChild(document.createElement("hr"));
    var all = document.createElement("a");
    all.className = "all"; all.href = meta("docs-repo") + "/releases"; all.textContent = "All releases on GitHub";
    menu.appendChild(all);
    button.disabled = false;
    if (versions.indexOf(version) >= 0 && version !== newest) {
      var note = document.querySelector(".old-version");
      note.innerHTML = '<div><span>These docs are for <code></code>. The latest release is <code></code>.</span>' +
        '<a href="' + base + 'latest/' + page + '">Go to the latest docs</a>' +
        '<span>Run <code>source-coop --version</code> to see yours.</span></div>';
      var codes = note.querySelectorAll("code");
      codes[0].textContent = version; codes[1].textContent = newest;
      note.hidden = false;
    }
  }).catch(function () {});

  // Search: the index (search.json, one entry for each heading) loads on
  // first use. A section matches when it holds every word typed; matches in
  // its title rank first.
  var box = document.getElementById("search"), results = document.getElementById("search-results");
  var css = document.querySelector('link[href$="assets/site.css"]');
  var pageRoot = css ? css.getAttribute("href").replace("assets/site.css", "") : "";
  var index = null;
  var esc = function (s) { return s.replace(/[&<>"]/g, function (c) { return "&#" + c.charCodeAt(0) + ";"; }); };
  function excerpt(text, words) {
    var lower = text.toLowerCase(), at = lower.indexOf(words[0]);
    var from = Math.max(0, at - 50), cut = text.slice(from, from + 160);
    var out = esc((from ? "…" : "") + cut + (from + 160 < text.length ? "…" : ""));
    words.forEach(function (w) {
      out = out.replace(new RegExp("(" + esc(w).replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "gi"), "<mark>$1</mark>");
    });
    return out;
  }
  function search() {
    var words = box.value.toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) { results.hidden = true; return; }
    if (!index) {
      fetch(pageRoot + "search.json").then(function (r) { return r.json(); }).then(function (got) { index = got; search(); });
      return;
    }
    var found = index.map(function (e) {
      var title = e.title.toLowerCase(), body = e.text.toLowerCase(), score = 0;
      for (var i = 0; i < words.length; i++) {
        var inTitle = title.indexOf(words[i]) >= 0, inBody = body.indexOf(words[i]) >= 0;
        if (!inTitle && !inBody) return null;
        score += (inTitle ? 10 : 0) + (inBody ? 1 : 0);
      }
      return { e: e, score: score };
    }).filter(Boolean).sort(function (a, b) { return b.score - a.score; }).slice(0, 8);
    results.innerHTML = found.length ? found.map(function (f) {
      var e = f.e;
      return '<a href="' + pageRoot + (e.page ? e.page + "/" : "") + "#" + e.id + '"><b>' + esc(e.title) + "</b>" +
        (e.title !== e.section ? "<small>" + esc(e.section) + "</small>" : "") +
        (e.text ? "<span>" + excerpt(e.text, words) + "</span>" : "") + "</a>";
    }).join("") : "<p>No sections match.</p>";
    results.hidden = false;
  }
  box.addEventListener("input", search);
  box.addEventListener("focus", function () { if (box.value) search(); });
  box.addEventListener("keydown", function (e) {
    var first = results.querySelector("a");
    if (e.key === "Enter" && first) { location.href = first.href; }
    if (e.key === "ArrowDown" && first) { e.preventDefault(); first.focus(); }
  });
  results.addEventListener("keydown", function (e) {
    var links = [].slice.call(results.querySelectorAll("a")), i = links.indexOf(document.activeElement);
    if (e.key === "ArrowDown" && i < links.length - 1) { e.preventDefault(); links[i + 1].focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); (i > 0 ? links[i - 1] : box).focus(); }
  });
  document.addEventListener("keydown", function (e) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || "");
    if (e.key === "/" && !typing) { e.preventDefault(); box.focus(); box.select(); }
    if (e.key === "Escape" && !results.hidden) { results.hidden = true; box.focus(); }
  });
  document.addEventListener("click", function (e) { if (!e.target.closest(".search")) results.hidden = true; });
})();
