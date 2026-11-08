// The demo player: a recorded SVG, still on its last frame until played, with
// play/pause, a scrub track marked at each step, and a drawer of the steps.
//
// The SVGs animate with one SMIL <animateTransform> (demo/record.py) that
// slides a filmstrip of frames. Browsers start an inlined SVG's animation at
// whatever time its clock had reached, so seeking through SMIL lands on the
// wrong frame: the player takes the keyframes out and moves the filmstrip
// itself, on its own clock. Each <figure class="demo" data-demo="NAME"> loads demos/NAME.svg and the
// steps in demos/NAME.json when it nears the screen.
(function () {
  var figures = document.querySelectorAll("figure.demo[data-demo]");
  if (!figures.length || !("SVGSVGElement" in window)) return;
  var css = document.querySelector('link[href$="assets/site.css"]');
  var root = css ? css.getAttribute("href").replace("assets/site.css", "") : "";
  var count = 0;

  var ICON = {
    play: '<svg aria-hidden="true" width="18" height="18" viewBox="0 0 20 20" fill="currentColor"><path d="M5 3.5v13a1 1 0 0 0 1.5.86l11-6.5a1 1 0 0 0 0-1.72l-11-6.5A1 1 0 0 0 5 3.5z"/></svg>',
    pause: '<svg aria-hidden="true" width="18" height="18" viewBox="0 0 20 20" fill="currentColor"><rect x="4" y="3" width="4" height="14" rx="1"/><rect x="12" y="3" width="4" height="14" rx="1"/></svg>',
    big: '<svg aria-hidden="true" width="30" height="30" viewBox="0 0 20 20" fill="currentColor"><path d="M6 3.5v13a1 1 0 0 0 1.5.86l10-6.5a1 1 0 0 0 0-1.72l-10-6.5A1 1 0 0 0 6 3.5z"/></svg>',
    list: '<svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1"/><circle cx="4.5" cy="12" r="1"/><circle cx="4.5" cy="18" r="1"/></svg>',
    close: '<svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>'
  };
  var fmt = function (s) { s = Math.max(0, Math.floor(s)); return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"); };
  var el = function (html) { var t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; };

  function setup(figure) {
    var name = figure.dataset.demo, n = ++count, id = "demo" + n;
    var player = el(
      '<div class="player">' +
        '<div class="player-view"><div class="player-screen poster"></div></div>' +
          '<div class="player-bar" hidden>' +
            '<button class="toggle" type="button" aria-label="Play">' + ICON.play + '</button>' +
            '<div class="player-track"><div class="rail"></div><div class="fill"></div>' +
              '<input type="range" min="0" step="0.05" value="0" aria-label="Seek"><div class="thumb"></div></div>' +
            '<span class="player-time" aria-hidden="true"></span>' +
          '</div>' +
      '</div>');
    var caption = figure.querySelector("figcaption");
    figure.insertBefore(player, caption);
    var screen = player.querySelector(".player-screen");
    var bar = player.querySelector(".player-bar");
    var toggle = bar.querySelector(".toggle");
    var track = bar.querySelector(".player-track");
    var range = track.querySelector("input");
    var time = bar.querySelector(".player-time");

    Promise.all([
      fetch(root + "demos/" + name + ".svg").then(function (r) { return r.text(); }),
      fetch(root + "demos/" + name + ".json").then(function (r) { return r.ok ? r.json() : { steps: [] }; }).catch(function () { return { steps: [] }; })
    ]).then(function (got) {
      // Every recording uses the same ids ("1", "a", …): prefix this one's, so
      // several on a page don't borrow each other's lines. Ink, not svg-term's
      // grey, behind the text.
      var text = got[0].replace(/\bid="([^"]+)"/g, 'id="' + id + '-$1"')
        .replace(/href="#([^"]+)"/g, 'href="#' + id + '-$1"')
        .replace(/fill="#282d35"/g, 'fill="#121A1B"');
      screen.innerHTML = text;
      var svg = screen.querySelector("svg");
      var w = parseFloat(svg.getAttribute("width")), h = parseFloat(svg.getAttribute("height"));
      svg.setAttribute("viewBox", "0 0 " + w + " " + h);
      svg.removeAttribute("width"); svg.removeAttribute("height");
      svg.setAttribute("role", "img");
      svg.setAttribute("aria-label", caption ? caption.textContent : name);
      var anim = svg.querySelector("animateTransform");
      // Trim the rows no frame uses, so a short demo isn't a tall empty box.
      var inner = anim.parentElement.closest("svg");
      var scale = inner.width.baseVal.value / inner.viewBox.baseVal.width;
      var rowH = parseFloat(inner.querySelector("[font-size]").getAttribute("font-size")) * 1.3;
      var lowest = Math.max.apply(null, [].map.call(anim.parentElement.querySelectorAll("use[y]"), function (u) { return parseFloat(u.getAttribute("y")); }).concat(0));
      // A band below the last row keeps the key overlay off the text.
      h = Math.min(h, inner.y.baseVal.value + (lowest + rowH) * scale + 64);
      svg.setAttribute("viewBox", "0 0 " + w + " " + h);
      screen.style.setProperty("--ratio", w + " / " + h);
      var film = {
        g: anim.parentElement,
        times: anim.getAttribute("keyTimes").split(";").map(Number),
        values: anim.getAttribute("values").split(";")
      };
      var dur = parseFloat(anim.getAttribute("dur")) || got[1].duration || 0;
      anim.remove();
      ready(film, dur, got[1].steps || [], got[1].keys || []);
    }).catch(function () {
      screen.classList.remove("poster");
      screen.innerHTML = '<img src="' + root + "demos/" + name + '.svg" alt="" style="width:100%;height:auto;display:block">';
    });

    function ready(film, dur, steps, keys) {
      var playing = false, started = false, frame = 0, current = -1;
      var now = dur, since = 0;
      range.max = dur;
      // The frame at time t: the last keyframe at or before it.
      function draw(t) {
        var at = t / dur, lo = 0, hi = film.times.length - 1;
        while (lo < hi) { var mid = (lo + hi + 1) >> 1; if (film.times[mid] <= at) lo = mid; else hi = mid - 1; }
        film.g.setAttribute("transform", "translate(" + film.values[lo] + ")");
      }

      var poster = el('<div class="player-poster"><button class="big" type="button" aria-label="Play the demo, ' +
        fmt(dur) + (steps.length ? ", " + steps.length + " steps" : "") + '">' + ICON.big + '</button>' +
        '<span class="badge" aria-hidden="true">Play · ' + fmt(dur) + (steps.length ? " · " + steps.length + " steps" : "") + '</span></div>');
      screen.appendChild(poster);

      var rows = [], ticks = [], rail, drawer;
      if (steps.length) {
        rail = el('<div class="player-rail"><button type="button" aria-expanded="false" aria-controls="' + id + '-steps" aria-label="Show the ' +
          steps.length + ' steps" title="Steps">' + ICON.list + '<span>' + steps.length + '</span></button></div>');
        drawer = el('<div class="player-steps" id="' + id + '-steps" hidden><header><span>Steps · ' + steps.length + '</span>' +
          '<button type="button" aria-label="Hide the steps">' + ICON.close + '</button></header><ol aria-label="Steps in this demo"></ol></div>');
        var view = player.querySelector(".player-view");
        view.appendChild(rail);
        view.appendChild(drawer);
        var list = drawer.querySelector("ol");
        steps.forEach(function (s, i) {
          var li = el('<li><button type="button"><span class="t"></span><span class="l"></span></button></li>');
          li.querySelector(".t").textContent = fmt(s.time);
          li.querySelector(".l").textContent = s.label;
          // A jump keeps the demo as it was: playing on from the step, or paused there.
          li.firstChild.addEventListener("click", function () { seek(s.time + 0.01); });
          list.appendChild(li);
          rows.push(li.firstChild);
          var tick = el('<div class="tick" aria-hidden="true"></div>');
          tick.style.left = (s.time / dur * 100) + "%";
          track.insertBefore(tick, range);
          ticks.push(tick);
        });
        // The rail keeps its place under the open drawer, so the demo
        // doesn't resize when the drawer opens.
        var open = function (yes) {
          drawer.hidden = !yes;
          (yes ? drawer.querySelector("header button") : rail.querySelector("button")).focus();
        };
        rail.querySelector("button").addEventListener("click", function () { open(true); });
        drawer.querySelector("header button").addEventListener("click", function () { open(false); });
        drawer.addEventListener("keydown", function (e) { if (e.key === "Escape") open(false); });
      }

      // The key just pressed, shown in the terminal's bottom right corner for a
      // second; one pressed again in a row counts up ("↓ ×2"). Typed text isn't
      // shown: it's on screen already.
      var cast = keys.length ? el('<div class="keycast" aria-hidden="true"></div>') : null, castHtml = "";
      if (cast) screen.appendChild(cast);
      function keycaps(t) {
        if (!cast) return;
        var span = 1.2, recent = [];
        if (started) keys.forEach(function (k) { if (k.time <= t && t - k.time < span) recent.push(k); });
        var html = "";
        if (recent.length) {
          var last = recent[recent.length - 1], n = 0;
          for (var i = recent.length - 1; i >= 0 && recent[i].key === last.key; i--) n++;
          var label = (last.key === "Enter" ? "⏎ Enter" : last.key) + (n > 1 ? " ×" + n : "");
          var fade = Math.max(0, Math.min(1, (span - (t - last.time)) / (span * 0.4)));
          html = '<kbd style="opacity:' + fade.toFixed(2) + '"></kbd>';
          if (html !== castHtml) { cast.innerHTML = html; cast.firstChild.textContent = label; castHtml = html; }
          else cast.firstChild.textContent = label;
          return;
        }
        if (castHtml) { cast.innerHTML = ""; castHtml = ""; }
      }

      function show() {
        var t = now;
        draw(t);
        keycaps(t);
        var pct = dur ? t / dur * 100 : 0;
        track.querySelector(".fill").style.width = pct + "%";
        track.querySelector(".thumb").style.left = pct + "%";
        range.value = t;
        var at = -1;
        steps.forEach(function (s, i) { if (s.time <= t + 0.02) at = i; });
        ticks.forEach(function (k, i) { k.classList.toggle("past", steps[i].time <= t); });
        if (at !== current) {
          if (rows[current]) rows[current].removeAttribute("aria-current");
          if (rows[at]) rows[at].setAttribute("aria-current", "step");
          current = at;
        }
        var label = at >= 0 ? " · " + steps[at].label : "";
        // Just the time: a step's name beside it would resize the track as it
        // changes. The drawer and the track's marks show the steps.
        time.textContent = fmt(t) + " / " + fmt(dur);
        range.setAttribute("aria-valuetext", fmt(t) + " of " + fmt(dur) + label);
      }
      function begin() {
        if (started) return;
        started = true;
        screen.classList.remove("poster");
        poster.hidden = true;
        bar.hidden = false;
      }
      function tick() {
        if (!playing) return;
        now = Math.min((performance.now() - since) / 1000, dur);
        if (now >= dur) { pause(); return; }
        show();
        frame = requestAnimationFrame(tick);
      }
      function play() {
        begin();
        if (now >= dur) now = 0;
        playing = true;
        since = performance.now() - now * 1000;
        toggle.innerHTML = ICON.pause; toggle.setAttribute("aria-label", "Pause");
        cancelAnimationFrame(frame); tick();
      }
      function pause() {
        playing = false;
        cancelAnimationFrame(frame);
        toggle.innerHTML = ICON.play; toggle.setAttribute("aria-label", "Play");
        show();
      }
      function seek(t) {
        begin();
        now = Math.max(0, Math.min(t, dur));
        since = performance.now() - now * 1000;
        show();
      }

      poster.querySelector("button").addEventListener("click", function () { play(); toggle.focus(); });
      toggle.addEventListener("click", function () { playing ? pause() : play(); });
      // A click on the demo plays or pauses it; a drag copies lines instead.
      var dragged = false;
      screen.addEventListener("click", function (e) {
        if (e.target.closest("button")) return;
        if (dragged) { dragged = false; return; }
        playing ? pause() : play();
      });

      // Copying: the browser can't select the recording's text sensibly (each
      // run of text is its own element), so a drag over the demo picks whole
      // rows, and letting go copies them as the screen shows them then.
      var inner = film.g.closest("svg"), strip = film.g.firstElementChild;
      var size = parseFloat(inner.querySelector("[font-size]").getAttribute("font-size")), rowH = size * 1.3;
      function rowsShowing() {
        // The frame showing, then its lines: a <use> of a shared symbol (a line
        // seen in several frames) or <text> written into the frame (a line seen
        // once, like a prompt being answered), placed by row and column.
        var x = -parseFloat((film.g.getAttribute("transform") || "").replace(/^translate\(/, "")) || 0;
        var shown = [].find.call(strip.children, function (f) { return Math.abs(parseFloat(f.getAttribute("x") || 0) - x) < 0.5; });
        var pieces = {}, rows = {};
        function add(row, t) {
          (pieces[row] = pieces[row] || []).push([Math.round(parseFloat(t.getAttribute("x") || 0) / 1.002), t.textContent]);
        }
        if (shown) [].forEach.call(shown.children, function (c) {
          if (c.tagName === "use") {
            var sym = inner.querySelector(c.getAttribute("href") || c.getAttribute("xlink:href"));
            var row = Math.round(parseFloat(c.getAttribute("y") || 0) / rowH);
            if (sym) [].forEach.call(sym.querySelectorAll("text"), function (t) { add(row, t); });
          } else if (c.tagName === "text") {
            add(Math.round((parseFloat(c.getAttribute("y") || size) - size) / rowH), c);
          }
        });
        Object.keys(pieces).forEach(function (r) {
          var line = "";
          pieces[r].sort(function (a, b) { return a[0] - b[0]; }).forEach(function (p) {
            while (line.length < p[0]) line += " ";
            line += p[1];
          });
          rows[r] = line.replace(/\s+$/, "");
        });
        return rows;
      }
      function rowAt(y) {
        return Math.max(0, Math.floor(new DOMPoint(0, y).matrixTransform(inner.getScreenCTM().inverse()).y / rowH));
      }
      function rowTop(r) {
        return new DOMPoint(0, r * rowH).matrixTransform(inner.getScreenCTM()).y - screen.getBoundingClientRect().top;
      }
      var from = null, pick = null;
      function unpick() { if (pick) { pick.remove(); pick = null; } from = null; }
      screen.addEventListener("pointerdown", function (e) {
        if (e.button !== 0 || e.pointerType === "touch" || e.target.closest("button")) return;
        from = { y: e.clientY, row: rowAt(e.clientY) };
        dragged = false;
      });
      window.addEventListener("pointermove", function (e) {
        if (!from || (!dragged && Math.abs(e.clientY - from.y) < 4)) return;
        dragged = true;
        if (!pick) { pick = el('<div class="pick" aria-hidden="true"></div>'); screen.appendChild(pick); }
        var lo = Math.min(from.row, rowAt(e.clientY)), hi = Math.max(from.row, rowAt(e.clientY));
        pick.style.top = rowTop(lo) + "px";
        pick.style.height = (rowTop(hi + 1) - rowTop(lo)) + "px";
      });
      window.addEventListener("pointerup", function (e) {
        if (!from) return;
        var a = from.row, b = rowAt(e.clientY), rows = rowsShowing(), lines = [];
        if (!dragged) { unpick(); return; }
        for (var r = Math.min(a, b); r <= Math.max(a, b); r++) if (rows[r] !== undefined) lines.push(rows[r]);
        var text = lines.join("\n");
        function note(msg) {
          var t = el('<div class="toast" role="status"></div>');
          t.textContent = msg;
          screen.appendChild(t);
          setTimeout(function () { t.remove(); unpick(); }, 1400);
        }
        from = null;
        if (!text) { unpick(); return; }
        var copied = navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject();
        copied.then(function () { note("Copied " + lines.length + (lines.length === 1 ? " line" : " lines")); },
                    function () { note("Couldn't copy: your browser didn't allow it"); });
      });
      window.addEventListener("pointercancel", unpick);
      range.addEventListener("input", function () { seek(parseFloat(range.value)); });
      show();
    }
  }

  // Load each demo as it nears the screen, so a page of them stays light.
  if ("IntersectionObserver" in window) {
    var seen = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { seen.unobserve(e.target); setup(e.target); } });
    }, { rootMargin: "600px 0px" });
    figures.forEach(function (f) { seen.observe(f); });
  } else {
    figures.forEach(setup);
  }
})();
