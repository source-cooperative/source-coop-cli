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
  // and lists every release, newest first. A build that isn't one of them (a PR preview, a local build)
  // stays in the menu as itself.
  var version = meta("docs-version"), base = meta("docs-base"), page = meta("docs-page");
  var select = document.getElementById("version");
  var inLatest = location.pathname.indexOf(base + "latest/") === 0;
  fetch(base + "versions.json").then(function (r) { return r.ok ? r.json() : Promise.reject(); }).then(function (listed) {
    var versions = listed.versions || [], newest = listed.latest;
    if (!versions.length || !newest) return;
    select.textContent = "";
    var add = function (value, label, selected) {
      var o = document.createElement("option");
      o.value = value; o.textContent = label; o.selected = selected;
      select.appendChild(o);
    };
    var known = versions.indexOf(version) >= 0;
    if (!known) add("", version.indexOf("pr-") === 0 ? "PR #" + version.slice(3) + " preview" : version, true);
    add("latest", "latest (" + newest + ")", known && inLatest);
    versions.forEach(function (v) { add(v, v, known && !inLatest && v === version); });
    select.disabled = false;
    select.addEventListener("change", function () {
      if (select.value) location.href = base + select.value + "/" + page + location.hash;
    });
    if (known && version !== newest) {
      var note = document.querySelector(".old-version");
      note.innerHTML = '<div><span>These docs are for <code></code>. The latest release is <code></code>.</span>' +
        '<a href="' + base + 'latest/' + page + '">Go to the latest docs</a>' +
        '<span>Run <code>source-coop --version</code> to see yours.</span></div>';
      var codes = note.querySelectorAll("code");
      codes[0].textContent = version; codes[1].textContent = newest;
      note.hidden = false;
    }
  }).catch(function () {});
})();
