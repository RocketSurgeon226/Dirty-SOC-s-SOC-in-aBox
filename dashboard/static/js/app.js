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
var CHIPS = [["Phone", "device-mobile"], ["Tablet", "tablet"], ["Laptop or computer", "device-laptop"],
             ["Smart TV", "device-tv"], ["Game console", "device-gamepad-2"], ["Smart speaker", "speaker"],
             ["Printer", "printer"], ["Camera or doorbell", "camera"], ["Smart plug or light", "bulb"],
             ["Router or Wi-Fi point", "router"]];

var state = null;       // the last data from the server
var openForms = {};     // mac -> true while that naming form is open (pauses redrawing)
var openDetails = {};   // key -> true for "How do I do that?" / "More details" sections left open
var yoursAnswer = {};   // mac -> "no" / "unsure" picked on "Is this yours?", kept across redraws
var flashTimer = null;

// Step-by-step help under a card's next step, by alert category. The steps follow the
// actions in analysis/translate/templates.py. New-device cards carry the naming form instead.
var DISCONNECT_STEP = "Disconnect it. On a phone, tablet or laptop, open Settings and turn Wi-Fi off. " +
  "For a computer plugged in with a cable, unplug the cable from the back. " +
  "For a TV, speaker, camera or other smart device, unplug its power.";
// "Still need help?" opens an AI assistant in a new tab with the alert already asked.
// Google's AI Mode (built on Gemini) needs no sign-in, and falls back to a normal Google search.
// To use something else, change this; the question is added on the end.
var AI_HELP_URL = "https://www.google.com/search?udm=50&q=";

// Generic words for the device, so household names like "Kid's Xbox" never leave the network.
var DEVICE_KIND = { "device-tv": "smart TV", "device-gamepad-2": "game console", "device-mobile": "phone",
                    "device-laptop": "computer", "speaker": "smart speaker", "router": "home router",
                    "printer": "printer", "camera": "camera", "tablet": "tablet", "bulb": "smart plug or light" };

function stillNeedHelp(a) {
  var kind = DEVICE_KIND[a.device_icon] || "device";
  var question = "My home network security monitor showed this alert about a " +
    kind + ": \u201c" + a.description + "\u201d It suggested: \u201c" + a.action + "\u201d " +
    "Can you explain what this means in plain language, without jargon, and walk me through what to do, step by step?";
  var box = el("div", "still-help");
  var link = el("a", "btn btn-got", "Still need help? Ask AI \u2197");
  link.href = AI_HELP_URL + encodeURIComponent(question);
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  box.appendChild(link);
  box.appendChild(el("p", "muted small", "Opens Google in a new tab. Only the alert is shared, not your device names."));
  return box;
}

var HELP = {
  malicious_contact: [
    DISCONNECT_STEP,
    "Run a virus scan. On Windows, open “Windows Security” from the Start menu and choose “Quick scan”. " +
      "Phones, Macs and smart devices don't need this step.",
    "Update its software. On a phone or computer, open Settings and look for “Software update”. " +
      "For a smart device, open the app it came with.",
    "Delete any apps you don't recognize, then reconnect it.",
    "If this alert comes back, ask someone you trust to look at the device, or contact its maker."
  ],
  plaintext_credentials: [
    "Think of the website or app you last signed in to on this device.",
    "Change that password, using a different device if you can. If you use the same password anywhere else, change it there too.",
    "Before you sign in from now on, check for a padlock next to the address at the top of the browser."
  ],
  // Only for a scan started by a home device; a scan from the internet needs nothing done.
  port_scan: [
    "Ask the household whether anyone is running a network or security tool on this device. If so, you can ignore this alert.",
    DISCONNECT_STEP,
    "Run a virus scan (on Windows, “Windows Security” then “Quick scan”) and update its software before reconnecting it.",
    "If it happens again after that, ask someone you trust to look at the device."
  ],
  outbound_volume: [
    "Check whether someone is backing up photos, uploading videos or on a video call on this device. " +
      "If this device always does that (a backup drive or media server, say), press “This is normal for this device” below.",
    "If not, " + DISCONNECT_STEP.charAt(0).toLowerCase() + DISCONNECT_STEP.slice(1),
    "Run a virus scan (on Windows, “Windows Security” then “Quick scan”) and update its software before reconnecting it."
  ],
  tracker_dns: [
    "iPhone or iPad: open Settings, then Safari (or Apps, then Safari), and turn on “Prevent Cross-Site Tracking”.",
    "Chrome: open Settings, then “Privacy and security”, and block third-party cookies.",
    "Firefox: open Settings, then “Privacy & Security”, and choose “Strict”.",
    "Smart TV or other device: in its settings, look for “Privacy”, “Ad tracking” or “Viewing data” and turn it off."
  ]
};

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
  "printer": [["path", { d: "M7 9V4h10v5" }], ["rect", { x: 4, y: 9, width: 16, height: 7, rx: 2 }],
              ["rect", { x: 7, y: 14, width: 10, height: 6 }]],
  "camera": [["rect", { x: 3, y: 7, width: 18, height: 13, rx: 2 }], ["path", { d: "M9 7l1.5-3h3L15 7" }],
             ["circle", { cx: 12, cy: 13.5, r: 3.5 }]],
  "tablet": [["rect", { x: 5, y: 3, width: 14, height: 18, rx: 2 }], ["path", { d: "M11 18h2" }]],
  "bulb": [["path", { d: "M9 18h6M10 21h4" }], ["path", { d: "M8.5 14.5A6 6 0 1 1 15.5 14.5c-.8.7-1.5 1.5-1.5 2.5h-4c0-1-.7-1.8-1.5-2.5z" }]],
  "arrow-right": [["path", { d: "M5 12h14M13 6l6 6-6 6" }]],
  "moon": [["path", { d: "M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z" }]],
  "sun": [["circle", { cx: 12, cy: 12, r: 4 }],
          ["path", { d: "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" }]],
  "smile": [["path", { d: "M8.5 9v.01M15.5 9v.01" }], ["path", { d: "M6.5 13.5a6 6 0 0 0 11 0" }]],
  "alert": [["path", { d: "M12 7v6" }], ["path", { d: "M12 17v.01" }]]
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
  var days = Math.floor(s / 86400);
  return days === 1 ? "Yesterday" : days + " days ago";
}
// "today", "Sunday" (this week) or "Oct 12", for "since ..." lines.
function sinceLabel(iso) {
  var d = new Date(iso), now = new Date();
  var days = Math.round((new Date(now.toDateString()) - new Date(d.toDateString())) / 86400000);
  if (days === 0) return "earlier today";
  if (days === 1) return "yesterday";
  if (days < 7) return d.toLocaleDateString(undefined, { weekday: "long" });
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
function times(n) { return n === 1 ? "once" : n === 2 ? "twice" : n.toLocaleString() + " times"; }
// A short confirmation at the top. action = { label: "Undo", run: fn } adds a button.
function flash(msg, action) {
  var f = byId("flash");
  if (!f) return;
  f.textContent = "";
  f.appendChild(el("span", "", msg));
  if (action) {
    var b = el("button", "btn btn-xs flash-btn", action.label);
    b.addEventListener("click", function () { f.hidden = true; action.run(); });
    f.appendChild(b);
  }
  f.hidden = false;
  clearTimeout(flashTimer);
  flashTimer = setTimeout(function () { f.hidden = true; }, action ? 10000 : 4000);
}
function setStatus(kind, text) {
  byId("status").className = "pill " + kind;
  byId("status-text").textContent = text;
}
function anyFormOpen() { return Object.keys(openForms).length > 0; }

// A collapsible section that stays open across the 5-second redraws.
function expander(key, label, cls) {
  var d = el("details", cls);
  d.appendChild(el("summary", "", label));
  if (openDetails[key]) d.open = true;
  d.addEventListener("toggle", function () {
    if (d.open) openDetails[key] = true; else delete openDetails[key];
  });
  return d;
}

// One plain sentence that helps a household recognize a device.
function deviceHint(d) {
  var parts = [];
  if (d.vendor) parts.push("Made by " + d.vendor + ".");
  if (d.hostname) parts.push("It calls itself “" + d.hostname + "”.");
  if (!parts.length && d.private_address) {
    parts.push("It hides its built-in ID, which phones, tablets and laptops usually do.");
  }
  return parts.join(" ") || "We couldn't tell who made it.";
}

// The technical identifiers, tucked away for anyone matching devices in a router app.
function deviceDetails(d) {
  var box = expander("dev-" + d.mac, "More details", "more small");
  if (d.ip) box.appendChild(el("div", "muted", "Where it is on your network: " + d.ip +
                                 " (your router's app lists devices this way)"));
  box.appendChild(el("div", "muted", "Its built-in ID: " + d.mac));
  return box;
}
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
      .catch(function () { err.textContent = "Couldn't reach the box. Try again."; err.hidden = false; });
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

// opts.handled draws a card the household already pressed "Got it" on, with "Not fixed yet".
function alertCard(a, opts) {
  opts = opts || {};
  var card = el("article", opts.handled ? "card handled" : "card severity-" + a.severity);
  var top = el("div", "card-top");
  var labels = { high: "Act now", medium: "Worth checking", low: "Just so you know" };
  if (opts.handled) top.appendChild(el("span", "badge badge-neutral", "Handled"));
  else top.appendChild(el("span", "badge badge-" + a.severity, labels[a.severity] || labels.low));
  top.appendChild(el("span", "muted small", whenLine(a)));
  card.appendChild(top);

  var dev = el("div", "card-device");
  dev.appendChild(icon(a.device_icon));
  var who = el("div");
  who.appendChild(el("span", "", a.device_name));
  var clue = deviceClue(a);
  if (clue) who.appendChild(el("div", "muted small", clue));
  dev.appendChild(who);
  card.appendChild(dev);
  card.appendChild(el("p", "card-desc", a.description));
  if (a.site) {
    var ipOnly = /^[0-9.:]+$/.test(a.site);
    card.appendChild(el("p", ipOnly ? "card-meaning small" : "card-site", ipOnly
      ? "We couldn't tell which site it was (its address was " + a.site + ")."
      : "The site or service: " + a.site));
  }
  if (a.meaning) card.appendChild(el("p", "card-meaning small", a.meaning));

  // A new-device card carries "Is this yours?" and the naming form instead of an action line.
  var nd = (!opts.handled && a.category === "new_device" && a.mac) ? deviceByMac(a.mac) : null;
  if (opts.handled) {
    var back = el("button", "btn btn-got", "Not fixed yet");
    back.addEventListener("click", function () { setAck(a.id, false, back); });
    var hf = el("div", "card-foot");
    hf.appendChild(back);
    card.appendChild(hf);
    return card;
  }
  if (nd) {
    card.appendChild(el("p", "muted small hint", deviceHint(nd)));
    card.appendChild(isThisYours(nd));
  } else if (a.action) {
    var act = el("div", "card-action");
    act.appendChild(icon("arrow-right"));
    act.appendChild(el("span", "", a.action));
    card.appendChild(act);
    var steps = helpSteps(a);
    if (steps) {
      var help = expander("help-" + a.id, "How do I do that?", "help");
      var ol = el("ol");
      steps.forEach(function (s) { ol.appendChild(el("li", "", s)); });
      help.appendChild(ol);
      help.appendChild(stillNeedHelp(a));
      card.appendChild(help);
    }
  }

  if (state.can_acknowledge && !nd) {
    var foot = el("div", "card-foot");
    var got = el("button", "btn btn-got", "Got it, I've handled this");
    got.addEventListener("click", function () { setAck(a.id, true, got); });
    foot.appendChild(got);
    if (state.can_mute && a.device_key && a.severity !== "high") {
      var normal = el("button", "btn btn-ghost", "This is normal for this device");
      normal.addEventListener("click", function () { markNormal(a, normal); });
      foot.appendChild(normal);
    }
    if (a.points > 0) foot.appendChild(el("span", "muted small points", "Fixing this adds " + a.points + " points to your grade"));
    card.appendChild(foot);
  }
  return card;
}

// "2 hr ago", or for something ongoing "Since Sunday · happened 137 times · latest 2 hr ago".
function whenLine(a) {
  var last = a.last_seen || a.timestamp;
  if (a.count > 1 && a.first_seen) {
    return "Since " + sinceLabel(a.first_seen) + " \u00b7 happened " + times(a.count) + " \u00b7 latest " + ago(last).toLowerCase();
  }
  return ago(last) + (a.count > 1 ? " \u00b7 happened " + times(a.count) : "");
}

// Who made it and where it is, so an "Unrecognized device" can still be found.
function deviceClue(a) {
  var dev = a.mac ? deviceByMac(a.mac) : null;
  var vendor = a.vendor || (dev && dev.vendor);
  var ip = a.device_ip || (dev && dev.ip);
  var named = a.device_name && !/^unrecognized|^your network/i.test(a.device_name);
  var parts = [];
  if (vendor) parts.push("Made by " + vendor);
  if (ip && (!named || !vendor)) parts.push("at " + ip + " on your network");
  return parts.join(" \u00b7 ");
}

function helpSteps(a) {
  if (a.category === "port_scan" && (!a.direction || a.direction === "inbound")) return null;
  return HELP[a.category] || null;
}

// "This is normal for this device": no more of these alerts for it. Undo lives on the Devices page.
function markNormal(a, btn) {
  btn.disabled = true;
  fetch(API + "/api/cards/" + encodeURIComponent(a.id) + "/normal", { method: "POST" })
    .then(function (r) { if (!r.ok) throw new Error("mute failed"); return refresh(); })
    .then(function () {
      flash("OK. We won't show this kind of alert for " + a.device_name + " again. You can change this on the Devices page.");
    })
    .catch(function () { btn.disabled = false; btn.textContent = "Couldn't save. Try again"; });
}

// "Is this yours?" for a new device: Yes opens naming, No and Not sure give next steps.
function isThisYours(d) {
  var box = el("div", "yours");
  box.appendChild(el("p", "yours-q", "Is this yours?"));
  var row = el("div", "form-actions");
  var yes = el("button", "btn btn-primary", "Yes");
  var no = el("button", "btn", "No");
  var unsure = el("button", "btn btn-ghost", "Not sure");
  row.appendChild(yes); row.appendChild(no); row.appendChild(unsure);
  box.appendChild(row);
  var naming = namingFlow(d);
  naming.hidden = true;
  box.appendChild(naming);
  var info = el("div", "yours-info"); info.hidden = true;
  box.appendChild(info);
  function show(title, steps) {
    info.textContent = "";
    info.appendChild(el("p", "", title));
    var ol = el("ol");
    steps.forEach(function (t) { ol.appendChild(el("li", "", t)); });
    info.appendChild(ol);
    info.hidden = false;
  }
  yes.addEventListener("click", function () {
    delete yoursAnswer[d.mac];
    info.hidden = true; naming.hidden = false;
    var start = naming.querySelector("button"); if (start) start.click();
  });
  function showNo() {
    show("Then someone else may be using your Wi-Fi. To lock them out:", [
      "Open your router's app, or look at the sticker on the router for how to sign in to it.",
      "Change the Wi-Fi password. Every device will need the new password, including yours.",
      "If your internet company gave you the router, they can do this for you over the phone."
    ]);
  }
  function showUnsure() {
    show("A quick way to find out what it is:", [
      "Check whether anyone just got a new phone, TV, speaker or other gadget, or has a guest over.",
      "Unplug or switch off one device you suspect, then come back to the Devices page in a few minutes.",
      "If this device now says “Last seen” a few minutes ago, the one you switched off was it. Give it a name."
    ]);
  }
  no.addEventListener("click", function () { yoursAnswer[d.mac] = "no"; showNo(); });
  unsure.addEventListener("click", function () { yoursAnswer[d.mac] = "unsure"; showUnsure(); });
  if (yoursAnswer[d.mac] === "no") showNo();
  else if (yoursAnswer[d.mac] === "unsure") showUnsure();
  return box;
}

// "Got it" (on = true) or "Not fixed yet" / Undo (on = false). Both can be reversed.
function setAck(id, on, btn) {
  if (btn) btn.disabled = true;
  fetch(API + "/api/cards/" + encodeURIComponent(id) + (on ? "/ack" : "/unack"), { method: "POST" })
    .then(function (r) { if (!r.ok) throw new Error("ack failed"); return refresh(); })
    .then(function () {
      if (on) flash("Marked as handled. You can find it in History any time.",
                    { label: "Undo", run: function () { setAck(id, false); } });
      else flash("Moved back to your home page.");
    })
    .catch(function () {
      if (btn) { btn.disabled = false; btn.textContent = "Couldn't save. Try again"; }
      else flash("Couldn't save that. Try again.");
    });
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
  var clue = deviceClue({ mac: d.mac, vendor: d.vendor, device_ip: d.ip, device_name: d.name });
  if (clue) card.appendChild(el("p", "muted small", clue));
  card.appendChild(el("p", "card-desc", "A new device joined your network."));
  card.appendChild(el("p", "muted small hint", deviceHint(d)));
  card.appendChild(isThisYours(d));
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

function things(n, one, many) { return n + (n === 1 ? " thing " + one : " things " + many); }

var HOME_LIMIT = 5;   // cards shown on the home page; the rest fold under "Ongoing"

// The one sentence at the top of the home page. It counts every open issue, so it always
// matches the cards below.
function renderSummary(counts) {
  var headline, sub, tone;
  if (counts.high) {
    headline = things(counts.high, "needs", "need") + " your attention";
    sub = "Start with the card marked “Act now”." +
      (counts.medium ? " " + things(counts.medium, "is", "are") + " also worth a look." : "");
    tone = "red";
  } else if (counts.medium) {
    headline = things(counts.medium, "is", "are") + " worth a look";
    sub = "Nothing urgent. Check when you have a minute.";
    tone = "yellow";
  } else {
    headline = "All is well";
    sub = "Nothing needs your attention. We'll let you know if anything changes.";
    tone = "green";
  }
  byId("summary").className = "hero hero-" + tone;
  var ic = byId("hero-icon");
  ic.textContent = "";
  ic.appendChild(icon(tone === "green" ? "smile" : "alert"));
  byId("headline").textContent = headline;
  byId("headline-sub").textContent = sub;

  var hl = state.health;
  var letter = hl.grade || "–";
  var band = /^[AB]/.test(letter) ? "green" : /^C/.test(letter) ? "yellow" : /^[DF]/.test(letter) ? "red" : "";
  var g = byId("grade");
  g.textContent = letter;
  g.className = "grade-letter" + (band ? " grade-" + band : "");
  var days = hl.window_days || 7;
  var basis = days === 1 ? "the last 24 hours" : "open alerts from the last " + days + " days";
  byId("grade-note").textContent = (hl.score !== undefined && hl.score !== null)
    ? hl.score + " out of 100 points, based on " + basis : "Based on " + basis;
  renderTrend(hl.trend);
  byId("trend-caption").hidden = byId("trend").hidden;
}

function renderAlertsPage() {
  var list = byId("alert-list");
  var main = [], minor = [];   // minor: "just so you know", folded away so they don't compete
  list.textContent = "";
  var hasNameCard = {};
  var counts = { high: 0, medium: 0, low: 0 };
  state.alerts.forEach(function (a) {
    if (a.category === "new_device" && a.mac) {
      var dev = deviceByMac(a.mac);
      if (dev && (dev.named || dev.skipped)) return;   // already handled: that card has done its job
      hasNameCard[a.mac] = true;
    }
    if (a.severity === "low") { minor.push(a); return; }
    counts[a.severity]++;
    main.push(alertCard(a));
  });
  pendingNaming().forEach(function (d) {
    if (hasNameCard[d.mac]) return;   // its new-device card already has the form
    counts.medium++;
    main.push(namingCard(d));
  });

  main.slice(0, HOME_LIMIT).forEach(function (c) { list.appendChild(c); });
  if (main.length > HOME_LIMIT) {
    var rest = main.length - HOME_LIMIT;
    var fold = expander("ongoing", "Ongoing: " + rest + " more worth checking", "more ongoing");
    var inner = el("div", "alert-list");
    main.slice(HOME_LIMIT).forEach(function (c) { inner.appendChild(c); });
    fold.appendChild(inner);
    list.appendChild(fold);
  }
  if (!list.firstChild) {   // keeps the left column from looking empty next to the grade
    list.appendChild(el("div", "card quiet muted", "No open alerts in the last 7 days."));
  }

  var mb = byId("minor");
  mb.textContent = "";
  if (minor.length) {
    var fyi = expander("minor", "FYI: " + minor.length + " minor note" + (minor.length === 1 ? "" : "s") +
                       " (nothing you need to do)", "more minor");
    var fyiList = el("div", "alert-list");
    minor.forEach(function (a) { fyiList.appendChild(alertCard(a)); });
    fyi.appendChild(fyiList);
    mb.appendChild(fyi);
  }
  var handled = state.handled || [];
  if (handled.length) {
    var link = el("a", "link small history-link",
                  "See " + handled.length + " handled alert" + (handled.length === 1 ? "" : "s") + " in History");
    link.href = "/history";
    mb.appendChild(link);
  }

  renderSummary(counts);
}

// ---- Devices page -------------------------------------------------------------------

var CATEGORY_WORDS = { outbound_volume: "sending lots of data", tracker_dns: "ad and tracker lookups",
                       port_scan: "scanning other devices", new_device: "new device alerts" };
var ONLINE_MS = 10 * 60 * 1000;

// Online now / last seen, and when it first joined.
function presence(d) {
  if (!d.last_seen) return "";
  var last = new Date(d.last_seen).getTime();
  var line = Date.now() - last < ONLINE_MS ? "Online now" : "Last seen " + ago(d.last_seen).toLowerCase();
  if (d.first_seen) line += " \u00b7 first joined " + new Date(d.first_seen).toLocaleDateString(undefined, { month: "short", day: "numeric" });
  return line;
}

function unmute(d, category, btn) {
  btn.disabled = true;
  fetch(API + "/api/mutes/remove", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_key: d.mute_keys[category], category: category }) })
    .then(function (r) { if (!r.ok) throw new Error(); return refresh(); })
    .then(function () { flash("We'll show those alerts for " + d.name + " again."); })
    .catch(function () { btn.disabled = false; btn.textContent = "Couldn't save. Try again"; });
}

function renderDevicesPage() {
  var box = byId("device-rows");
  box.textContent = "";
  var counts = {};
  state.devices.forEach(function (d) { counts[d.name] = (counts[d.name] || 0) + 1; });
  // Unnamed first, then newest to join, so the ones that need a decision are on top.
  var sorted = state.devices.slice().sort(function (x, y) {
    if (x.named !== y.named) return x.named ? 1 : -1;
    return (y.first_seen || "").localeCompare(x.first_seen || "");
  });
  sorted.forEach(function (d) {
    var row = el("div", "device-row" + (d.named ? "" : " unnamed"));
    var head = el("div", "device-head");
    head.appendChild(icon(d.icon));
    head.appendChild(el("span", "dname", d.name));
    head.appendChild(el("span", "spacer"));
    if (d.guessed) head.appendChild(el("span", "muted small", "Our best guess"));
    else if (!d.named) head.appendChild(el("span", "muted small", d.skipped ? "Not named" : "New"));
    row.appendChild(head);
    var p = presence(d);
    if (p) row.appendChild(el("div", "small presence" + (/^Online/.test(p) ? " online" : ""), p));
    if (!d.named || d.guessed || counts[d.name] > 1) row.appendChild(el("div", "muted small", deviceHint(d) +
      (counts[d.name] > 1 && d.ip ? " This one is at " + d.ip + "." : "")));
    (d.muted || []).forEach(function (c) {
      var m = el("div", "muted small muted-line", "Ignoring " + (CATEGORY_WORDS[c] || c) + " (you said it's normal). ");
      var b = el("button", "btn btn-xs", "Show them again");
      b.addEventListener("click", function () { unmute(d, c, b); });
      m.appendChild(b);
      row.appendChild(m);
    });
    row.appendChild(deviceDetails(d));
    row.appendChild(namingFlow(d));
    box.appendChild(row);
  });
  byId("no-devices").hidden = state.devices.length > 0;
}

// ---- History page -------------------------------------------------------------------

// "Today", "Yesterday", or a date like "Mon, Oct 12", in the viewer's own time zone.
function dayLabel(iso) {
  var d = new Date(iso), today = new Date();
  var days = Math.round((new Date(today.toDateString()) - new Date(d.toDateString())) / 86400000);
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  return d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
}

function renderHistoryPage() {
  var box = byId("history-list");
  box.textContent = "";
  var handled = state.handled || [];
  var lastDay = null, list = null;
  handled.forEach(function (a) {   // newest first, so each day's heading comes once
    var day = dayLabel(a.timestamp);
    if (day !== lastDay) {
      box.appendChild(el("h2", "history-day", day));
      list = el("div", "alert-list");
      box.appendChild(list);
      lastDay = day;
    }
    list.appendChild(alertCard(a, { handled: true }));
  });
  if (!handled.length) {
    box.appendChild(el("div", "card quiet muted", "Nothing here yet. Alerts you mark as handled will show up here."));
  }
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
    row.appendChild(el("div", "muted small", deviceHint(d) + " Is this one of yours?"));
    row.appendChild(deviceDetails(d));
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

var RESTART_TIP = "Try restarting the box: unplug it, wait 10 seconds, and plug it back in.";

// True when the box can't read Suricata's log, so nothing new is being detected.
function notWatching() {
  return state.source === "pi" && state.alert_source === "suricata" && !state.eve_readable;
}

// A plain message for the household, with the technical reason folded away for whoever set it up.
function renderNotice() {
  var n = byId("notice");
  if (!n) return;
  var problem = state.analysis && state.analysis.error;
  var message, details = [];
  if (notWatching()) {
    message = "The box can't see your network traffic right now, so it can't spot problems. " + RESTART_TIP;
    details.push("Can't read Suricata's alert log (eve.json). Check the --eve path and file permissions.");
    if (problem) details.push("Analysis service: " + problem);
  } else if (problem) {
    message = "Some features are having trouble, so alerts may be simpler than usual. Your network is still being watched. " +
      "If this message doesn't go away, " + RESTART_TIP.charAt(0).toLowerCase() + RESTART_TIP.slice(1);
    details.push("Analysis service: " + problem + ". Showing basic Suricata alerts instead.");
  }
  n.textContent = "";
  n.hidden = !message;
  if (!message) return;
  n.appendChild(el("p", "", message));
  var more = expander("notice", "Technical details (for whoever set this up)", "more small");
  details.forEach(function (t) { more.appendChild(el("div", "", t)); });
  n.appendChild(more);
}

function render() {
  if (!state || anyFormOpen()) return;   // don't wipe a form someone is typing in
  var badge = byId("setup-count");
  var waiting = pendingNaming().length;
  badge.textContent = String(waiting);
  badge.hidden = waiting === 0;
  renderNotice();
  if (PAGE === "devices") renderDevicesPage();
  else if (PAGE === "history") renderHistoryPage();
  else if (PAGE === "setup") renderSetupPage();
  else renderAlertsPage();
}

//Dark mode

//The button shows what it switches to. base.html applies the saved choice before the page draws.
function renderThemeToggle() {
  var btn = byId("theme-toggle");
  if (!btn) return;
  var dark = document.documentElement.getAttribute("data-theme") === "dark";
  btn.textContent = "";
  btn.appendChild(icon(dark ? "sun" : "moon"));
  btn.appendChild(el("span", "", dark ? "Light mode" : "Dark mode"));
  btn.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
}

var themeBtn = byId("theme-toggle");
if (themeBtn) {
  themeBtn.addEventListener("click", function () {
    var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("theme", next); } catch (e) {}   //private windows can refuse; it still switches
    renderThemeToggle();
  });
}
renderThemeToggle();

// ---- Talking to the server ----------------------------------------------------------

function refresh() {
  return fetch(API + "/api/state", { cache: "no-store" })
    .then(function (r) { if (!r.ok) throw new Error("bad status"); return r.json(); })
    .then(function (data) {
      state = data;
      if (data.source === "demo") setStatus("demo", "Demo mode \u00b7 sample data");
      else if (notWatching()) setStatus("down", "Not watching right now");
      else if (data.stale) setStatus("down", data.last_activity
        ? "No network activity since " + ago(data.last_activity).toLowerCase() : "Can't see network activity");
      else setStatus("live", "Watching \u00b7 last checked " + ago(data.last_activity).toLowerCase());
      render();
    })
    .catch(function () { setStatus("down", "Can't reach the box. Check it's plugged in."); });
}

refresh();
setInterval(refresh, POLL_MS);
