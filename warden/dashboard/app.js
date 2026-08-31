"use strict";
// Warden dashboard — dependency-free. Uses only fetch + DOM. Text-safe rendering.

const app = document.getElementById("app");
const foot = document.getElementById("footstat");
let view = "overview";
let currentSession = null;
let timer = null;

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "onclick") n.addEventListener("click", v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null) continue;
    n.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
  }
  return n;
}

async function api(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

function fmtTs(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}

// ---------- Overview ----------
async function renderOverview() {
  const o = await api("/api/overview");
  const stats = el("div", { class: "grid stats" },
    stat(o.sessions, "sessions recorded", ""),
    stat(o.blocked_total, "egress blocked", o.blocked_total > 0 ? "bad" : "ok"),
    stat(Object.keys(o.agents).length, "agents seen", ""),
    stat(o.tampered_sessions, "tampered logs", o.tampered_sessions > 0 ? "bad" : "ok"),
  );

  const blockedCard = el("div", { class: "card egress" },
    el("h2", {}, "Top blocked destinations"),
    o.top_blocked.length
      ? el("ul", {}, o.top_blocked.map(([h, n]) =>
          el("li", { class: "row" },
            el("span", { class: "dot deny" }),
            el("span", { class: "host mono" }, h),
            el("span", { class: "why" }, n + "×"))))
      : el("div", { class: "muted" }, "Nothing blocked yet — no undisclosed egress observed."));

  const hostsCard = el("div", { class: "card egress" },
    el("h2", {}, "Most-contacted allowed hosts"),
    o.top_hosts.length
      ? el("ul", {}, o.top_hosts.map(([h, n]) =>
          el("li", { class: "row" },
            el("span", { class: "dot allow" }),
            el("span", { class: "host mono" }, h),
            el("span", { class: "muted", style: "margin-left:auto" }, n + "×"))))
      : el("div", { class: "muted" }, "No network activity recorded yet."));

  const children = [
    stats,
    el("div", { class: "grid two", style: "margin-top:16px" }, blockedCard, hostsCard),
  ];

  if (o.drift && o.drift.length) {
    const driftCard = el("div", { class: "card", style: "margin-top:16px; border-color: var(--warn)" },
      el("h2", { style: "color: var(--warn)" }, "⚠ Behavioral drift detected (possible rug-pull)"),
      el("div", { class: "muted", style: "margin-bottom:8px" },
        "These skills contacted a host in a later run they never contacted before:"),
      el("ul", {}, o.drift.map(d =>
        el("li", { class: "row", onclick: () => openSession(d.session), style: "cursor:pointer" },
          el("span", { class: "dot deny" }),
          el("span", { class: "mono" }, d.key),
          el("span", { class: "why" }, "+ " + d.new_hosts.join(", ") +
            "  (run " + d.run_index + "/" + d.total_runs + ")")))));
    children.push(driftCard);
  }

  app.replaceChildren(...children);
  foot.textContent = o.sessions + " sessions · " + o.blocked_total + " blocked" +
    (o.drift && o.drift.length ? " · " + o.drift.length + " drift" : "");
}

function stat(n, label, kind) {
  return el("div", { class: "card stat " + (kind || "") },
    el("div", { class: "n" }, String(n)),
    el("div", { class: "l" }, label));
}

function riskBadge(risk) {
  const cls = { critical: "risk-crit", high: "risk-high", medium: "risk-med",
                low: "risk-low", none: "risk-none" }[risk.level] || "risk-none";
  return el("span", { class: "pill " + cls, title: (risk.reasons || []).join("; ") },
    risk.score + " " + risk.level);
}

// ---------- Sessions list ----------
async function renderSessions() {
  const rows = await api("/api/sessions");
  if (!rows.length) {
    app.replaceChildren(el("div", { class: "empty" },
      "No sessions yet. Run: ", el("span", { class: "mono" }, "warden run claude")));
    return;
  }
  const body = el("tbody", {}, rows.map(r => {
    const blocked = r.blocked_count > 0;
    const risk = r.risk || { score: 0, level: "none" };
    return el("tr", { class: "session-row", onclick: () => openSession(r.id) },
      el("td", { class: "mono" }, r.id),
      el("td", {}, r.agent || (r.command ? r.command.split(" ")[0] : "—")),
      el("td", {}, el("span", { class: "pill " + (r.mode === "enforce" ? "enforce" : "observe") }, r.mode || "—")),
      el("td", {}, riskBadge(risk)),
      el("td", {}, String(r.allowed_count)),
      el("td", {}, blocked
        ? el("span", { class: "pill block" }, r.blocked_count + " blocked")
        : el("span", { class: "muted" }, "0")),
      el("td", {}, r.integrity_ok
        ? el("span", { class: "pill clean" }, "intact")
        : el("span", { class: "pill tamper" }, "tampered")),
      el("td", { class: "muted" }, r.exit === 0 || r.exit ? String(r.exit) : "—"));
  }));
  const table = el("table", {},
    el("thead", {}, el("tr", {},
      ["Session", "Agent", "Mode", "Risk", "Allowed", "Blocked", "Integrity", "Exit"]
        .map(h => el("th", {}, h)))),
    body);
  app.replaceChildren(el("div", { class: "card" }, table));
  foot.textContent = rows.length + " sessions";
}

// ---------- Session detail ----------
async function openSession(id) {
  currentSession = id;
  view = "session";
  const s = await api("/api/session/" + id);
  const blocked = s.blocked_count > 0;

  const risk = s.risk || { score: 0, level: "none", reasons: [] };
  const banner = risk.score >= 25
    ? el("div", { class: "banner bad" },
        el("div", {}, "Risk " + risk.score + "/100 (" + risk.level.toUpperCase() + ")"),
        el("ul", { style: "margin:6px 0 0; font-weight:400; font-size:13px" },
          risk.reasons.map(r => el("li", {}, r))))
    : el("div", { class: "banner ok" },
        "Low risk (" + risk.score + "/100). No undisclosed egress of concern.");

  const meta = el("div", { class: "card" },
    el("div", { class: "kv" },
      kv("Command", el("span", { class: "mono" }, s.command || "—")),
      kv("Agent", s.agent || "—"),
      kv("Policy", s.policy || "—"),
      kv("Mode", el("span", { class: "pill " + (s.mode === "enforce" ? "enforce" : "observe") }, s.mode)),
      kv("Directory", el("span", { class: "mono" }, s.cwd || "—")),
      kv("Exit", (s.exit === 0 || s.exit ? String(s.exit) : "—") + "  ·  " + (s.duration_s ?? "?") + "s"),
      kv("Started", fmtTs(s.ts)),
      kv("Integrity", s.integrity_ok
        ? el("span", { class: "pill clean" }, "intact — " + s.integrity_msg)
        : el("span", { class: "pill tamper" }, "TAMPERED — " + s.integrity_msg))));

  const warned = s.warned || [];
  const egress = el("div", { class: "card egress" },
    el("h2", {}, "Network egress (" + s.allowed_count + " allowed, " + s.blocked_count +
      " blocked" + (warned.length ? ", " + warned.length + " warned" : "") + ")"),
    (s.allowed.length + s.blocked.length + warned.length)
      ? el("ul", {}, [
          ...s.blocked.map(b => egRow(b, "deny")),
          ...warned.map(w => egRow(w, "warn")),
          ...s.allowed.map(a => egRow(a, "allow")),
        ])
      : el("div", { class: "muted" }, "No network activity observed."));

  // Deep recording (files & processes), only if present.
  const deepCounts = s.deep_counts || {};
  let deepCard = null;
  if (Object.keys(deepCounts).length) {
    const label = { "proc.exec": "processes", "fs.open": "files read",
                    "fs.create": "files created", "fs.write": "files written",
                    "ipc.connect": "IPC connects", "proc.fork": "forks" };
    deepCard = el("div", { class: "card egress" },
      el("h2", {}, "Deep recording — files & processes"),
      el("div", { class: "muted", style: "margin-bottom:8px" },
        Object.entries(deepCounts).map(([k, n]) => (label[k] || k) + ": " + n).join("  ·  ")),
      el("ul", {}, (s.deep_events || []).slice(0, 60).map(ev =>
        el("li", { class: "row" },
          el("span", { class: "mono muted", style: "min-width:90px" }, ev.kind),
          el("span", { class: "mono" }, ev.path || (ev.args ? ev.args.join(" ") : ""))))));
  }

  const timeline = el("div", { class: "card" },
    el("h2", {}, "Timeline"),
    el("table", {},
      el("tbody", {}, (s.timeline || []).map(ev =>
        el("tr", {},
          el("td", { class: "mono muted", style: "white-space:nowrap" }, fmtClock(ev.ts)),
          el("td", { class: "mono" }, ev.kind),
          el("td", { class: "muted" }, tlDetail(ev)))))));

  app.replaceChildren(
    el("div", { style: "margin-bottom:14px; display:flex; gap:12px; align-items:center" },
      el("button", { class: "back", onclick: () => { view = "sessions"; render(); } }, "← Sessions"),
      el("span", { class: "mono muted" }, id)),
    banner, meta,
    el("div", { style: "height:16px" }), egress,
    ...(deepCard ? [el("div", { style: "height:16px" }), deepCard] : []),
    el("div", { style: "height:16px" }), timeline);
  foot.textContent = "session " + id;
}

function fmtClock(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

function tlDetail(ev) {
  const d = ev.data || {};
  if (ev.kind === "net.connect" || ev.kind === "net.request")
    return (d.host || "") + (d.verdict ? " (" + d.verdict + ")" : "");
  if (ev.kind === "child.start") return (d.cmd || []).join(" ").slice(0, 80);
  if (ev.kind === "child.exit") return "exit " + d.code + " · " + d.duration_s + "s";
  if (ev.kind === "policy.compiled") return "sandbox profile applied";
  if (ev.kind === "proxy.up") return "egress proxy :" + d.port;
  if (ev.kind === "session.start") return (d.policy || "") + (d.enforce ? " · enforce" : " · observe");
  return "";
}

function egRow(e, kind) {
  const label = { allow: null, warn: "let through (monitor) — not in allow-list",
                  deny: "blocked — not in allow-list" }[kind];
  const dotClass = kind === "allow" ? "allow" : kind === "warn" ? "warn" : "deny";
  return el("li", { class: "row" },
    el("span", { class: "dot " + dotClass }),
    el("span", { class: "host mono" }, e.host),
    e.method ? el("span", { class: "muted", style: "margin-left:8px" }, e.method) : null,
    label ? el("span", { class: "why", style: kind === "warn" ? "color:var(--warn)" : "" }, label) : null);
}

function kv(k, v) {
  return el("div", { style: "display:contents" },
    el("div", { class: "k" }, k),
    el("div", {}, typeof v === "string" ? document.createTextNode(v) : v));
}

// ---------- router ----------
async function render() {
  try {
    if (view === "overview") await renderOverview();
    else if (view === "sessions") await renderSessions();
    else if (view === "session" && currentSession) await openSession(currentSession);
  } catch (e) {
    app.replaceChildren(el("div", { class: "empty" }, "Could not load: " + e.message));
  }
}

document.querySelectorAll(".tabs button").forEach(b => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach(x => x.classList.remove("active"));
    b.classList.add("active");
    view = b.dataset.view;
    currentSession = null;
    render();
  });
});

function tick() {
  if (document.getElementById("live").checked) render();
}
timer = setInterval(tick, 3000);
render();
