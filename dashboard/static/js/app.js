// Owner: Aron — Fetch alerts/devices from the API and render cards.
// SOC-In-a-Box dashboard script (Owner: Aron).
//
// One script for all three pages. It asks the server for fresh data every few seconds and
// draws the page named in <body data-page="...">: "alerts", "devices" or "setup".
// Everything that comes from the network is shown with textContent, never as HTML.

var API = "";
var POLL_MS = 5000;
var PAGE = (document.body.dataset && document.body.dataset.page) || "alerts";

// What the naming form offers: label -> icon.
var CHIPS = [["Smart TV", "device-tv"], ["Game console", "device-gamepad-2"], ["Phone", "device-mobile"],
             ["Laptop", "device-laptop"], ["Smart speaker", "speaker"]];

var state = null;       // the last data from the server
var openForms = {};     // mac -> true while that naming form is open (pauses redrawing)
var flashTimer = null;

// ---- Icons: small inline SVGs, so the page works with no internet ------------------

var SVG_NS = "http://www.w3.org/2000/svg";
var ICON_SHAPES = {
  "device-unknown": [["rect", { x: 6, y: 3, width: 12, height: 18, rx: 2 }],
                     ["path", { d: "M10.5 9.5a1.5 1.5 0 1 1 2.2 1.3c-.5.3-.7.7-.7 1.2" }], ["path", { d: "M12 15.5v.01" }]],
  "device-tv": [["rect", { x: 3, y: 5, width: 18, height: 12, rx: 2 }], ["path", { d: "M8 21h8" }]],
  "device-gamepad-2": [["path", { d: "M6 8h12a4 4 0 0 1 4 4v1a3 3 0 0 1-5.2 2L15 13H9l-1.8 2A3 3 0 0 1 2 13v-1a4 4 0 0 1 4-4z" }],
                       ["path", { d: "M7 10.5v3M5.5 12h3" }], ["path", { d: "M16 11v.01M18 13v.01" }]],
  "device-mobile": [["rect", { x: 7, y: 3, width: 10, height: 18, rx: 2 }], ["path", { d: "M11 18h2" }]],
  "device-laptop": [["rect", { x: 5, y: 6, width: 14, height: 10, rx: 1 }], ["path", { d: "M3 20h18" }]],
  "speaker": [["rect", { x: 6, y: 3, width: 12, height: 18, rx: 2 }], ["circle", { cx: 12, cy: 14, r: 3 }],
              ["path", { d: "M12 7v.01" }]],
  "router": [["rect", { x: 4, y: 14, width: 16, height: 6, rx: 2 }], ["path", { d: "M8 17v.01M12 17v.01" }],
             ["path", { d: "M12 14V9" }], ["path", { d: "M9 7a4.2 4.2 0 0 1 6 0" }]],
  "arrow-right": [["path", { d: "M5 12h14M13 6l6 6-6 6" }]]
};

function icon(name) {
  var shapes = ICON_SHAPES[name] || ICON_SHAPES["device-unknown"];
  var svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  shapes.forEach(function (s) {
    var node = document.createElementNS(SVG_NS, s[0]);
    for (var attr in s[1]) node.setAttribute(attr, s[1][attr]);
    svg.appendChild(node);
  });
  return svg;
}

// ---- Small helpers ------------------------------------------------------------------

function el(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
function byId(id) { return document.getElementById(id); }
function ago(iso) {
  var s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "Just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " hr ago";
  return Math.floor(s / 86400) + " days ago";
}
function flash(msg) {
  var f = byId("flash");
  if (!f) return;
  f.textContent = msg; f.hidden = false;
  clearTimeout(flashTimer);
  flashTimer = setTimeout(function () { f.hidden = true; }, 4000);
}
function setStatus(kind, text) {
  byId("status").className = "pill " + kind;
  byId("status-text").textContent = text;
}
function anyFormOpen() { return Object.keys(openForms).length > 0; }
function deviceByMac(mac) {
  for (var i = 0; i < state.devices.length; i++) {
    if (state.devices[i].mac === mac) return state.devices[i];
  }
  return null;
}
function pendingNaming() {   // devices that still need a name and haven't been skipped
  return state.devices.filter(function (d) { return !d.named && !d.skipped; });
}

// ---- Naming a device ----------------------------------------------------------------

// The naming form for one device. opts.autoOpen opens it straight away.
function namingFlow(d, opts) {
  opts = opts || {};
  var flow = el("div", "naming-flow");
  var startBtn = el("button", d.named ? "btn" : "btn btn-primary", d.named ? "Rename" : "Name this device");
  var form = el("div"); form.hidden = true;

  form.appendChild(el("p", "muted small", "What is this device?"));
  var input = el("input", "name-input");
  input.type = "text"; input.placeholder = "e.g. Kid's Xbox"; input.maxLength = 40;
  var chosenIcon = d.named ? d.icon : "device-unknown";
  var chips = el("div", "chip-row");
  CHIPS.forEach(function (pair) {
    var c = el("button", "chip", pair[0]);
    c.type = "button";
    c.addEventListener("click", function () { input.value = pair[0]; chosenIcon = pair[1]; input.focus(); });
    chips.appendChild(c);
  });
  var err = el("p", "form-error", "Enter a name first"); err.hidden = true;
  var actions = el("div", "form-actions");
  var save = el("button", "btn btn-primary", "Save");
  var skip = el("button", "btn btn-ghost", d.named ? "Cancel" : "Skip for now");
  actions.appendChild(save); actions.appendChild(skip);
  form.appendChild(chips); form.appendChild(input); form.appendChild(err); form.appendChild(actions);

  function open() {
    startBtn.hidden = true; form.hidden = false; err.hidden = true;
    input.value = d.named ? d.name : "";
    openForms[d.mac] = true;
    input.focus();
  }
  function done(message) {
    delete openForms[d.mac];
    if (message) flash(message);
    refresh();
  }
  function post(path, body, cb) {
    fetch(API + "/api/devices/" + encodeURIComponent(d.mac) + "/" + path, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {})
    }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(cb)
      .catch(function () { err.textContent = "Couldn't reach the Pi. Try again."; err.hidden = false; });
  }

  startBtn.addEventListener("click", open);
  input.addEventListener("input", function () { if (input.value.trim()) err.hidden = true; });
  save.addEventListener("click", function () {
    var name = input.value.trim();
    if (!name) { err.textContent = "Enter a name first"; err.hidden = false; return; }
    post("name", { name: name, icon: chosenIcon }, function (res) {
      if (!res.ok) { err.textContent = res.j.error || "Couldn't save that name."; err.hidden = false; return; }
      done("Saved. Future alerts will call this device \u201c" + res.j.name + "\u201d.");
    });
  });
  skip.addEventListener("click", function () {
    if (d.named) { done(); return; }                       // Cancel on a rename
    post("skip", {}, function () { done(); });             // Skip on a new device
  });

  flow.appendChild(startBtn); flow.appendChild(form);
  if (opts.autoOpen) setTimeout(open, 0);
  return flow;
}

// ---- Alerts page --------------------------------------------------------------------

function alertCard(a) {
  var card = el("article", "card severity-" + a.severity);
  var top = el("div", "card-top");
  var labels = { high: "High", medium: "Medium", low: "Low" };
  top.appendChild(el("span", "badge badge-" + a.severity, labels[a.severity] || "Low"));
  top.appendChild(el("span", "muted small", ago(a.timestamp) + (a.count > 1 ? " \u00b7 seen " + a.count + " times" : "")));
  card.appendChild(top);

  var dev = el("div", "card-device");
  dev.appendChild(icon(a.device_icon));
  dev.appendChild(el("span", "", a.device_name));
  card.appendChild(dev);
  card.appendChild(el("p", "card-desc", a.description));

  // A new-device card carries the naming form itself (instead of a plain action line).
  var nd = (a.category === "new_device" && a.mac) ? deviceByMac(a.mac) : null;
  if (nd) {
    card.appendChild(namingFlow(nd));
  } else if (a.action) {
    var act = el("div", "card-action");
    act.appendChild(icon("arrow-right"));
    act.appendChild(el("span", "", a.action));
    card.appendChild(act);
  }

  if (state.can_acknowledge && !nd) {
    var foot = el("div", "card-foot");
    var got = el("button", "btn btn-ghost btn-xs", "Got it");
    got.addEventListener("click", function () { acknowledge(a.id, got); });
    foot.appendChild(got);
    card.appendChild(foot);
  }
  return card;
}

function acknowledge(id, btn) {
  btn.disabled = true;
  fetch(API + "/api/cards/" + encodeURIComponent(id) + "/ack", { method: "POST" })
    .then(function (r) { if (!r.ok) throw new Error("ack failed"); return refresh(); })
    .catch(function () { btn.disabled = false; btn.textContent = "Couldn't save. Try again"; });
}

// A card of its own for an unnamed device that has no new-device alert.
function namingCard(d) {
  var card = el("article", "card severity-medium");
  var top = el("div", "card-top");
  top.appendChild(el("span", "badge badge-medium", "New device"));
  card.appendChild(top);
  var dev = el("div", "card-device");
  dev.appendChild(icon(d.icon));
  dev.appendChild(el("span", "", d.name));
  card.appendChild(dev);
  card.appendChild(el("p", "card-desc", "A new device joined your network. Was this you?"));
  card.appendChild(namingFlow(d));
  return card;
}

// Seven small bars, one per day, oldest first.
function renderTrend(points) {
  var box = byId("trend");
  box.textContent = "";
  if (!points || !points.length) { box.hidden = true; return; }
  box.hidden = false;
  box.setAttribute("aria-label", "Health score for the last " + points.length + " days: " +
    points.map(function (p) { return p.score; }).join(", "));
  points.forEach(function (p) {
    var col = el("div", "trend-col");
    var bar = el("div", "trend-bar" + (p.color ? " " + p.color : ""));
    bar.style.height = Math.max(4, Math.round(p.score * 0.4)) + "px";
    bar.setAttribute("title", p.date + ": " + p.score);
    var d = new Date(p.date + "T00:00:00Z");
    col.appendChild(bar);
    col.appendChild(el("span", "trend-label", isNaN(d) ? "" : "SMTWTFS".charAt(d.getUTCDay())));
    box.appendChild(col);
  });
}

function renderAlertsPage() {
  var list = byId("alert-list");
  list.textContent = "";
  var hasNameCard = {};
  state.alerts.forEach(function (a) {
    if (a.category === "new_device" && a.mac) {
      var dev = deviceByMac(a.mac);
      if (dev && (dev.named || dev.skipped)) return;   // already handled: that card has done its job
      hasNameCard[a.mac] = true;
    }
    list.appendChild(alertCard(a));
  });
  pendingNaming().forEach(function (d) {
    if (!hasNameCard[d.mac]) list.appendChild(namingCard(d));   // its new-device card already has the form
  });
  if (!list.firstChild) {
    var ok = el("div", "card all-clear severity-low");
    ok.appendChild(el("div", "big", "Everything is running smoothly"));
    ok.appendChild(el("p", "muted small", "No unusual activity in the last 24 hours."));
    list.appendChild(ok);
  }

  var hl = state.health;
  var hasScore = hl.score !== undefined && hl.score !== null;   // Brady's 0-100 score vs. a plain grade
  var gradeEl = byId("grade");
  gradeEl.textContent = hasScore ? String(hl.score) : hl.grade;
  gradeEl.className = "health-grade" + (hasScore && hl.color ? " tone-" + hl.color : "");
  byId("grade-note").textContent =
    hasScore ? (hl.label ? hl.label + " \u00b7 " : "") + "out of 100, last 24 hours" : hl.note;
  renderTrend(hasScore ? hl.trend : null);

  var dl = byId("device-list");
  dl.textContent = "";
  state.devices.forEach(function (d) {
    var li = el("li", d.named ? "" : "unnamed");
    li.appendChild(icon(d.icon));
    li.appendChild(el("span", "dname", d.name));
    dl.appendChild(li);
  });
  byId("no-devices").hidden = state.devices.length > 0;
}

// ---- Devices page -------------------------------------------------------------------

function renderDevicesPage() {
  var box = byId("device-rows");
  box.textContent = "";
  state.devices.forEach(function (d) {
    var row = el("div", "device-row" + (d.named ? "" : " unnamed"));
    var head = el("div", "device-head");
    head.appendChild(icon(d.icon));
    head.appendChild(el("span", "dname", d.name));
    head.appendChild(el("span", "spacer"));
    if (!d.named) head.appendChild(el("span", "muted small", d.skipped ? "Not named" : "New") );
    row.appendChild(head);
    if (!d.named && d.ip) row.appendChild(el("div", "muted small", "Seen at " + d.ip));
    row.appendChild(namingFlow(d));
    box.appendChild(row);
  });
  byId("no-devices").hidden = state.devices.length > 0;
}

// ---- Set up page --------------------------------------------------------------------

function renderSetupPage() {
  var box = byId("setup-list");
  box.textContent = "";
  var pending = pendingNaming();
  pending.forEach(function (d) {
    var row = el("div", "device-row unnamed");
    var head = el("div", "device-head");
    head.appendChild(icon(d.icon));
    head.appendChild(el("span", "dname", d.name));
    row.appendChild(head);
    row.appendChild(el("div", "muted small", d.ip ? "Seen at " + d.ip + ". Is this one of yours?" : "Is this one of yours?"));
    row.appendChild(namingFlow(d, { autoOpen: true }));
    box.appendChild(row);
  });
  if (!pending.length) {
    var ok = el("div", "card all-clear severity-low");
    ok.appendChild(el("div", "big", "All set"));
    ok.appendChild(el("p", "muted small", "Every device on your network has a name."));
    var link = el("a", "link small", "See all devices");
    link.href = "/devices";
    ok.appendChild(link);
    box.appendChild(ok);
  }
}

// ---- Drawing ------------------------------------------------------------------------

function renderNotice() {
  var n = byId("notice");
  if (!n) return;
  var problem = state.analysis && state.analysis.error;
  if (problem) {
    n.textContent = "The analysis service had a problem (" + problem + "). Anything it couldn't provide is showing basic data from the Pi instead.";
    n.hidden = false;
  } else if (state.source === "pi" && state.alert_source === "suricata" && !state.eve_readable) {
    n.textContent = "Can't read Suricata's alert log (eve.json). Check the --eve path and file permissions.";
    n.hidden = false;
  } else { n.hidden = true; }
}

function render() {
  if (!state || anyFormOpen()) return;   // don't wipe a form someone is typing in
  var badge = byId("setup-count");
  var waiting = pendingNaming().length;
  badge.textContent = String(waiting);
  badge.hidden = waiting === 0;
  renderNotice();
  if (PAGE === "devices") renderDevicesPage();
  else if (PAGE === "setup") renderSetupPage();
  else renderAlertsPage();
}

// ---- Talking to the server ----------------------------------------------------------

function refresh() {
  return fetch(API + "/api/state", { cache: "no-store" })
    .then(function (r) { if (!r.ok) throw new Error("bad status"); return r.json(); })
    .then(function (data) {
      state = data;
      setStatus(data.source === "demo" ? "demo" : "live",
                data.source === "demo" ? "Demo data (no Pi attached)"
                  : "Live from the Pi \u00b7 " + (data.alert_source === "analysis" ? "analysis service" : "basic Suricata alerts"));
      render();
    })
    .catch(function () { setStatus("down", "Can't reach the Pi"); });
}

refresh();
setInterval(refresh, POLL_MS);
