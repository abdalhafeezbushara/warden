"use strict";

// Dependency-free by design: the console is bundled with Driftward and never calls
// a remote origin. All untrusted session values are inserted as text nodes.
const app = document.getElementById("app");
const foot = document.getElementById("footstat");
const tabs = [...document.querySelectorAll("[data-view]")];
const live = document.getElementById("live");
function viewFromHash() {
  if (location.hash === "#sessions") return "sessions";
  if (location.hash === "#behavior") return "behavior";
  return "overview";
}
let view = viewFromHash();
let currentSession = null;
let refreshTimer = null;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2), value);
    } else if (value !== null && value !== undefined) {
      node.setAttribute(key, String(value));
    }
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

async function api(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error("Request failed (" + response.status + ")");
  return response.json();
}

function fmtTs(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : "—";
}

function fmtClock(ts) {
  return ts ? new Date(ts * 1000).toLocaleTimeString() : "";
}

function principalLabel(session = {}) {
  const subject = session.subject || {};
  if (subject.kind === "mcp") return "MCP · " + (subject.name || "server");
  return session.agent || "Command";
}

function setTabs(next) {
  tabs.forEach(tab => {
    const active = tab.dataset.view === next;
    tab.classList.toggle("active", active);
    if (active) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  });
}

function icon(name) {
  const symbols = {
    shield: "◆", block: "⊘", alert: "!", timer: "◷", key: "⌁",
    network: "↗", receipt: "✓", process: "⌘", backend: "▣"
  };
  return el("span", { class: "mini-icon", "aria-hidden": "true" }, symbols[name] || "•");
}

function statusPill(status) {
  const value = status || "unknown";
  return el("span", { class: "pill status-" + value }, value.replace("-", " "));
}

function modePill(mode) {
  return el("span", { class: "pill mode-" + (mode || "unknown") }, mode || "—");
}

function riskBadge(risk = {}) {
  const level = risk.level || "none";
  return el("span", {
    class: "pill risk-" + level,
    title: (risk.reasons || []).join("; ")
  }, String(risk.score || 0), " · ", level);
}

function metric(value, label, tone = "", note = "") {
  return el("article", { class: "metric " + tone },
    el("div", { class: "metric-value" }, String(value)),
    el("div", { class: "metric-label" }, label),
    note ? el("div", { class: "metric-note" }, note) : null);
}

function sectionHead(title, copy) {
  return el("div", { class: "section-head" },
    el("div", {}, el("h2", {}, title), copy ? el("p", {}, copy) : null));
}

function emptyState(title, copy, command) {
  return el("div", { class: "empty-state" },
    el("div", { class: "empty-symbol", "aria-hidden": "true" }, "◇"),
    el("h2", {}, title),
    el("p", {}, copy),
    command ? el("code", {}, command) : null);
}

function capability(name, value, ok) {
  return el("div", { class: "capability" },
    el("span", { class: "cap-dot " + (ok ? "on" : "off") }),
    el("span", {}, name),
    el("strong", {}, value));
}

async function renderOverview() {
  const [overview, caps] = await Promise.all([api("/api/overview"), api("/api/capabilities")]);
  const approvedDrift = ((overview.behavior || {}).findings || []).length;
  const concerns = overview.tampered_sessions + overview.degraded_sessions +
    overview.timed_out_sessions + overview.high_risk_sessions + approvedDrift;
  const posture = concerns ? "Review needed" : "Protected";
  const postureTone = concerns ? "attention" : "secure";

  const hero = el("section", { class: "hero " + postureTone },
    el("div", { class: "hero-copy" },
      el("div", { class: "eyebrow" }, "Runtime posture"),
      el("h1", {}, posture),
      el("p", {}, concerns
        ? concerns + " security signal" + (concerns === 1 ? "" : "s") + " need attention."
        : "All recorded agent activity is within policy and every receipt is intact.")),
    el("div", { class: "posture-mark", "aria-label": posture }, concerns ? "!" : "✓"));

  const capStrip = el("section", { class: "cap-strip", "aria-label": "Local capabilities" },
    capability("Enforcement", caps.enforcement ? "available" : "unavailable", caps.enforcement),
    capability("Egress", caps.hard_egress ? "hard block" : "best effort", caps.hard_egress),
    capability("Strict read", caps.strict_read ? "supported" : "limited", caps.strict_read),
    capability("Behavior diff", caps.behavioral_integrity ? "signed baselines" : "unavailable", caps.behavioral_integrity),
    el("div", { class: "cap-meta" }, "v" + caps.version + " · " + caps.backend + " · Python " + caps.python));

  const metrics = el("section", { class: "metrics", "aria-label": "Security metrics" },
    metric(overview.sessions, "Sessions", "", "recorded locally"),
    metric(overview.blocked_total, "Blocked egress", overview.blocked_total ? "danger" : "good"),
    metric(overview.high_risk_sessions, "High-risk", overview.high_risk_sessions ? "danger" : "good"),
    metric(overview.degraded_sessions, "Degraded", overview.degraded_sessions ? "warn" : "good"),
    metric(overview.timed_out_sessions, "Timed out", overview.timed_out_sessions ? "warn" : ""),
    metric(overview.tampered_sessions, "Tampered", overview.tampered_sessions ? "danger" : "good"));

  const activity = el("section", { class: "panel" },
    sectionHead("Recent sessions", "The latest agent, MCP, and command executions."),
    overview.recent.length ? recentList(overview.recent) :
      emptyState("No sessions recorded", "Start an agent through Driftward to build your local security history.", "driftward run claude"));

  const blocked = destinationPanel(
    "Top blocked destinations",
    "Denied by network policy",
    overview.top_blocked,
    "blocked",
    "No blocked destinations. Policy violations will appear here.");
  const allowed = destinationPanel(
    "Allowed destinations",
    "Most contacted approved hosts",
    overview.top_hosts,
    "allowed",
    "No allowed network activity recorded.");

  const parts = [hero, capStrip, metrics,
    el("div", { class: "content-grid" }, activity, el("div", { class: "stack" }, blocked, allowed))];

  if (approvedDrift) parts.splice(3, 0, approvedDriftPanel(overview.behavior.findings));
  else if (overview.drift && overview.drift.length && !(overview.behavior.baselines || []).length) {
    parts.splice(3, 0, driftPanel(overview.drift));
  }
  app.replaceChildren(...parts);
  foot.textContent = overview.sessions + " sessions · " + overview.blocked_total +
    " requests blocked · backend " + caps.backend;
}

function recentList(rows) {
  return el("div", { class: "recent-list" }, rows.map(row => {
    const button = el("button", { class: "recent-row", onclick: () => openSession(row.id) },
      el("span", { class: "recent-main" },
        el("strong", {}, row.subject && row.subject.kind === "mcp"
          ? principalLabel(row) : (row.agent || row.command || "Command")),
        el("span", { class: "mono" }, row.id)),
      statusPill(row.status),
      riskBadge(row.risk),
      el("span", { class: "recent-meta" }, row.blocked_count + " blocked", el("small", {}, fmtTs(row.ts))),
      el("span", { class: "chevron", "aria-hidden": "true" }, "›"));
    return button;
  }));
}

function destinationPanel(title, subtitle, rows, kind, empty) {
  return el("section", { class: "panel compact" },
    sectionHead(title, subtitle),
    rows.length ? el("ol", { class: "destinations" }, rows.map(([host, count]) =>
      el("li", {},
        el("span", { class: "dest-dot " + kind }),
        el("code", {}, host),
        el("strong", {}, count + "×")))) : el("p", { class: "quiet" }, empty));
}

function driftPanel(rows) {
  return el("section", { class: "notice warning" },
    el("div", { class: "notice-icon", "aria-hidden": "true" }, "↗"),
    el("div", {},
      el("h2", {}, "Behavioral drift detected"),
      el("p", {}, "A recurring agent contacted destinations not seen in its earlier runs."),
      el("div", { class: "drift-list" }, rows.map(item =>
        el("button", { onclick: () => openSession(item.session) },
          el("strong", {}, item.key),
          el("span", {}, "New: " + item.new_hosts.join(", ")),
          el("small", {}, "Run " + item.run_index + " of " + item.total_runs))))));
}

function approvedDriftPanel(rows) {
  return el("section", { class: "notice danger" },
    el("div", { class: "notice-icon", "aria-hidden": "true" }, "!"),
    el("div", {},
      el("h2", {}, "Approved behavior changed"),
      el("p", {}, "The latest execution contains capabilities outside a signed baseline."),
      el("div", { class: "drift-list" }, rows.map(item =>
        el("button", { onclick: () => openSession(item.session) },
          el("strong", {}, item.subject),
          el("span", {}, item.new_count + " new · " + item.highest_severity + " severity"),
          el("small", {}, item.error || summarizeNew(item.new)))))));
}

function summarizeNew(groups = {}) {
  const values = [];
  for (const [category, capabilities] of Object.entries(groups)) {
    for (const cap of capabilities) values.push(category + ": " + cap.action + " " + cap.resource);
  }
  return values.slice(0, 4).join(" · ") || "Runtime or policy identity changed";
}

async function renderBehavior() {
  const state = await api("/api/behavior");
  const coverage = state.coverage || { subjects: 0, approved: 0, unapproved: 0 };
  const title = el("div", { class: "page-title" },
    el("div", {}, el("div", { class: "eyebrow" }, "Agent behavioral integrity"),
      el("h1", {}, "Behavior"),
      el("p", {}, "Git diff for agent and MCP capabilities, measured against explicit signed approval.")),
    el("span", { class: "count-badge" }, coverage.approved + "/" + coverage.subjects + " approved"));

  const metrics = el("section", { class: "metrics behavior-metrics", "aria-label": "Behavior coverage" },
    metric(coverage.subjects, "Subjects", "", "agents, MCP servers, and commands"),
    metric(coverage.approved, "Approved", coverage.approved ? "good" : "", "signed baselines"),
    metric(state.stable.length, "Stable", state.stable.length ? "good" : "", "matches approval"),
    metric(state.findings.length, "Drifted", state.findings.length ? "danger" : "good", "needs review"),
    metric(coverage.unapproved, "Unapproved", coverage.unapproved ? "warn" : "good", "observed, not trusted"));

  const findings = el("section", { class: "panel behavior-panel" },
    sectionHead("Drift inbox", "New capabilities are never learned automatically."),
    state.findings.length ? el("div", { class: "behavior-list" }, state.findings.map(item =>
      el("button", { class: "behavior-row severity-" + item.highest_severity,
          onclick: () => openSession(item.session) },
        el("span", { class: "severity-mark" }, "!"),
        el("span", {}, el("strong", {}, item.subject),
          el("small", {}, item.error || summarizeNew(item.new))),
        el("span", { class: "pill risk-" + item.highest_severity }, item.highest_severity),
        el("span", { class: "behavior-count" }, item.new_count + " new")))) :
      emptyState("No approved drift", "Approved subjects match their signed behavior baselines."));

  const unapproved = el("section", { class: "panel behavior-panel" },
    sectionHead("Waiting for approval", "Observed sessions are evidence—not trusted behavior."),
    state.unbaselined.length ? el("div", { class: "behavior-list" }, state.unbaselined.map(item =>
      el("button", { class: "behavior-row", onclick: () => openSession(item.latest_session) },
        el("span", { class: "severity-mark neutral" }, "?"),
        el("span", {}, el("strong", {}, item.subject),
          el("small", {}, item.sessions + " session" + (item.sessions === 1 ? "" : "s") +
            " · " + item.capability_count + " observed capabilities")),
        el("code", {}, "driftward baseline approve " + item.latest_session)))) :
      el("p", { class: "quiet" }, "Every observed subject has an approved baseline."));

  const baselines = el("section", { class: "panel behavior-panel" },
    sectionHead("Signed baselines", "Local, portable approvals verified with Ed25519."),
    state.baselines.length ? el("div", { class: "baseline-grid" }, state.baselines.map(item =>
      el("article", { class: "baseline-card " + (item.valid ? "valid" : "invalid") },
        el("div", {}, el("strong", {}, item.name),
          el("span", { class: "receipt-" + (item.valid ? "ok" : "bad") }, item.valid ? "✓ Verified" : "! Invalid")),
        el("p", {}, item.capability_count + " approved capabilities"),
        el("code", {}, (item.public_key || "").slice(0, 18) + (item.public_key ? "…" : ""))))) :
      emptyState("No approved baselines", "Inspect a clean session, then approve it explicitly.",
        "driftward behavior && driftward baseline approve"));

  app.replaceChildren(title, metrics, findings, unapproved, baselines);
  foot.textContent = coverage.approved + " approved · " + state.findings.length +
    " drifted · all behavior data stays local";
}

async function renderSessions() {
  const rows = await api("/api/sessions");
  const title = el("div", { class: "page-title" },
    el("div", {}, el("div", { class: "eyebrow" }, "Evidence explorer"),
      el("h1", {}, "Sessions"),
      el("p", {}, "Search and inspect tamper-evident execution receipts.")),
    el("span", { class: "count-badge" }, rows.length + " total"));

  if (!rows.length) {
    app.replaceChildren(title, emptyState("No sessions recorded", "Run an agent through Driftward, then return here.", "driftward run claude"));
    foot.textContent = "0 sessions";
    return;
  }

  const search = el("input", { type: "search", placeholder: "Search agent, command, policy, or ID…", "aria-label": "Search sessions" });
  const mode = selectFilter("Mode", [["", "All modes"], ["enforce", "Enforce"], ["observe", "Observe"], ["degraded", "Degraded"]]);
  const risk = selectFilter("Risk", [["", "All risks"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["none", "None"]]);
  const resultText = el("span", { class: "filter-result", role: "status" });
  const list = el("div", { class: "session-table-wrap" });

  function update() {
    const query = search.value.trim().toLowerCase();
    const filtered = rows.filter(row => {
      const haystack = [row.id, row.agent, row.command, row.policy].join(" ").toLowerCase();
      return (!query || haystack.includes(query)) &&
        (!mode.select.value || row.mode === mode.select.value) &&
        (!risk.select.value || (row.risk || {}).level === risk.select.value);
    });
    resultText.textContent = filtered.length + " shown";
    list.replaceChildren(filtered.length ? sessionsTable(filtered) :
      emptyState("No matching sessions", "Try clearing one of the filters."));
  }
  [search, mode.select, risk.select].forEach(control => control.addEventListener("input", update));

  const filters = el("section", { class: "filters", "aria-label": "Session filters" },
    el("div", { class: "search-wrap" }, el("span", { "aria-hidden": "true" }, "⌕"), search),
    mode.label, risk.label, resultText);
  app.replaceChildren(title, filters, list);
  update();
  foot.textContent = rows.length + " sessions";
}

function selectFilter(label, options) {
  const select = el("select", { "aria-label": label }, options.map(([value, text]) =>
    el("option", { value }, text)));
  return { select, label: el("label", { class: "select-wrap" }, el("span", { class: "sr-only" }, label), select) };
}

function sessionsTable(rows) {
  return el("table", { class: "sessions-table" },
    el("thead", {}, el("tr", {}, ["Session", "Agent / command", "Status", "Mode", "Backend", "Risk", "Egress", "Receipt"]
      .map(value => el("th", { scope: "col" }, value)))),
    el("tbody", {}, rows.map(row => {
      const tr = el("tr", { tabindex: "0", role: "link", "aria-label": "Open session " + row.id,
        onclick: () => openSession(row.id),
        onkeydown: event => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            openSession(row.id);
          }
        }},
        el("td", {}, el("code", {}, row.id), el("small", {}, fmtTs(row.ts))),
        el("td", {}, el("strong", {}, principalLabel(row)), el("small", { class: "truncate" }, row.command || "—")),
        el("td", {}, statusPill(row.status)),
        el("td", {}, modePill(row.mode)),
        el("td", {}, el("span", { class: "backend-label" }, row.backend || "—")),
        el("td", {}, riskBadge(row.risk)),
        el("td", {}, row.blocked_count
          ? el("span", { class: "blocked-count" }, row.blocked_count + " blocked")
          : el("span", { class: "quiet" }, row.allowed_count + " allowed")),
        el("td", {}, row.integrity_ok
          ? el("span", { class: "receipt-ok" }, "✓ Intact")
          : el("span", { class: "receipt-bad" }, "! Tampered")));
      return tr;
    })));
}

async function openSession(id) {
  currentSession = id;
  view = "session";
  setTabs("");
  const session = await api("/api/session/" + encodeURIComponent(id));
  const risk = session.risk || { score: 0, level: "none", reasons: [] };
  const behaviorDiff = session.behavior_diff;
  const behaviorValue = !behaviorDiff ? "Unapproved" :
    (behaviorDiff.status === "stable" ? "Stable" :
      (behaviorDiff.status === "drift" ? "Drift detected" : "Baseline invalid"));
  const behaviorNote = !behaviorDiff ? "observation has no signed baseline" :
    (behaviorDiff.status === "stable" ? "matches signed approval" :
      ((behaviorDiff.new_count || 0) + " new · " + (behaviorDiff.highest_severity || "unknown") + " severity"));

  const actions = el("div", { class: "detail-actions" },
    el("button", { class: "button secondary", onclick: () => copyCommand(session.command) }, "Copy command"),
    el("button", { class: "button primary", onclick: () => exportJson(session) }, "Export JSON"));
  const header = el("div", { class: "detail-head" },
    el("button", { class: "back", onclick: () => navigate("sessions") }, "← Sessions"),
    el("div", { class: "detail-title" },
      el("div", {}, el("h1", {}, principalLabel(session) + " session"), el("code", {}, id)),
      actions));

  const banner = el("section", { class: "risk-banner risk-banner-" + risk.level },
    el("div", { class: "risk-score" }, el("strong", {}, risk.score + "/100"), el("span", {}, risk.level + " risk")),
    el("div", {}, el("h2", {}, risk.score >= 25 ? "Review this execution" : "No material security signals"),
      risk.reasons && risk.reasons.length
        ? el("ul", {}, risk.reasons.map(reason => el("li", {}, reason)))
        : el("p", {}, "Activity stayed within policy and the receipt remains intact.")));

  const evidence = el("section", { class: "evidence-grid", "aria-label": "Session evidence" },
    evidenceCard("shield", "Sandbox", session.mode === "enforce" ? "Enforced" : session.mode, session.backend || "unknown backend", session.mode === "enforce"),
    evidenceCard("network", "Network", session.blocked_count + " blocked", session.allowed_count + " allowed · " + session.warned_count + " warned", session.blocked_count === 0),
    evidenceCard("key", "Environment", (session.env_scrubbed.count || 0) + " scrubbed", "credential exposure reduced", true),
    evidenceCard("process", "Deep trace", Object.keys(session.deep_counts || {}).length ? "Captured" : "No events", deepSummary(session.deep_counts), true),
    evidenceCard("alert", "Behavior", behaviorValue, behaviorNote,
      behaviorDiff && behaviorDiff.status === "stable"),
    evidenceCard("receipt", "Receipt", session.integrity_ok ? "Intact" : "Tampered", session.integrity_msg || "", session.integrity_ok));

  const metadata = el("section", { class: "panel" },
    sectionHead("Execution", "How this process was launched."),
    el("dl", { class: "metadata" },
      datum("Command", el("code", {}, session.command || "—")),
      datum("Principal", principalLabel(session)),
      session.subject && session.subject.definition_sha256
        ? datum("Definition digest", el("code", {}, session.subject.definition_sha256)) : null,
      datum("Working directory", el("code", {}, session.cwd || "—")),
      datum("Policy", session.policy || "—"),
      datum("Started", fmtTs(session.ts)),
      datum("Duration", session.duration_s === null || session.duration_s === undefined ? "—" : session.duration_s + "s"),
      datum("Exit", session.exit === null || session.exit === undefined ? "—" : String(session.exit)),
      datum("Status", statusPill(session.status)),
      datum("Mode", modePill(session.mode))));

  const network = networkPanel(session);
  const behavior = behaviorSessionPanel(session);
  const deep = deepPanel(session);
  const timeline = timelinePanel(session.timeline || []);

  app.replaceChildren(header, banner, evidence, metadata, behavior, network, deep, timeline);
  foot.textContent = "session " + id + " · " + session.records + " signed records";
  app.focus({ preventScroll: true });
}

function behaviorSessionPanel(session) {
  const manifest = session.behavior || { capabilities: {}, coverage: {} };
  const subject = manifest.subject || {};
  const result = session.behavior_diff;
  let body;
  if (!result) {
    body = el("div", { class: "behavior-empty" },
      el("p", {}, "This is an observation, not trusted behavior. Review its capabilities before approval."),
      el("code", {}, "driftward baseline approve " + session.id));
  } else if (result.status === "untrusted-baseline") {
    body = el("div", { class: "notice danger" }, el("strong", {}, "Baseline rejected"),
      el("p", {}, result.error || "The baseline signature could not be verified."));
  } else if (result.status === "stable") {
    body = el("div", { class: "behavior-stable" },
      el("span", { class: "receipt-ok" }, "✓ Matches approved behavior"),
      el("p", {}, "No capabilities appeared outside the signed baseline."));
  } else {
    body = el("div", { class: "finding-list" },
      ...(result.identity_changes || []).map(change =>
        findingRow(change.severity, "identity", change.reason)),
      ...(result.findings || []).map(finding =>
        findingRow(finding.severity, finding.category,
          finding.capability.action + " " + finding.capability.resource, finding.reason)));
  }
  const counts = Object.entries(manifest.capabilities || {}).map(([category, caps]) =>
    el("span", { class: "cap-count" }, el("strong", {}, String(caps.length)), " " + category));
  return el("section", { class: "panel detail-panel" },
    sectionHead("Behavioral integrity", result
      ? "Compared with explicit signed approval."
      : "No baseline is created or updated automatically."),
    el("div", { class: "cap-counts" },
      el("span", { class: "cap-count" }, el("strong", {}, subject.key || "unknown"), " principal"),
      subject.definition_sha256
        ? el("span", { class: "cap-count", title: subject.definition_sha256 },
          el("strong", {}, subject.definition_sha256.slice(0, 12) + "…"), " definition") : null),
    el("div", { class: "cap-counts" }, counts), body);
}

function findingRow(severity, category, title, reason = "") {
  return el("div", { class: "finding-row severity-" + severity },
    el("span", { class: "pill risk-" + severity }, severity),
    el("span", {}, el("strong", {}, category + " · " + title),
      reason ? el("small", {}, reason) : null));
}

function evidenceCard(symbol, label, value, note, good) {
  return el("article", { class: "evidence-card " + (good ? "good" : "attention") },
    icon(symbol), el("div", {}, el("small", {}, label), el("strong", {}, value), el("span", {}, note || "—")));
}

function deepSummary(counts = {}) {
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
  return total ? total + " filesystem/process events" : "enable --deep for full telemetry";
}

function datum(term, value) {
  return el("div", {}, el("dt", {}, term), el("dd", {}, typeof value === "string" ? value : value));
}

function networkPanel(session) {
  const events = [
    ...(session.blocked || []).map(event => ({ ...event, kind: "blocked" })),
    ...(session.warned || []).map(event => ({ ...event, kind: "warned" })),
    ...(session.allowed || []).map(event => ({ ...event, kind: "allowed" }))
  ];
  return el("section", { class: "panel detail-panel" },
    sectionHead("Network decisions", session.allowed_count + " allowed · " + session.blocked_count + " blocked · " + session.warned_count + " warned"),
    events.length ? el("div", { class: "event-list" }, events.map(event =>
      el("div", { class: "event-row" },
        el("span", { class: "dest-dot " + event.kind }),
        el("code", {}, event.host),
        el("span", { class: "event-detail" }, event.method || "", event.detail ? " · " + event.detail : ""),
        el("span", { class: "decision " + event.kind }, event.kind)))) :
      el("p", { class: "quiet" }, "No network activity observed."));
}

function deepPanel(session) {
  const events = session.deep_events || [];
  return el("section", { class: "panel detail-panel" },
    sectionHead("Filesystem & process trace", deepSummary(session.deep_counts)),
    events.length ? el("div", { class: "event-list scroll-list" }, events.slice(0, 100).map(event =>
      el("div", { class: "event-row" },
        el("span", { class: "event-kind" }, event.kind),
        el("code", {}, event.path || (event.args || []).join(" ") || "—"),
        el("time", {}, fmtClock(event.ts))))) :
      el("p", { class: "quiet" }, "No deep events captured for this session. Use --deep on supported platforms."));
}

function timelinePanel(events) {
  const rows = events.map(event => el("li", {},
    el("time", {}, fmtClock(event.ts)),
    el("span", { class: "timeline-dot" }),
    el("div", {},
      el("strong", {}, event.kind),
      el("p", {}, timelineDetail(event)))));
  return el("section", { class: "panel detail-panel" },
    sectionHead("Signed timeline", events.length + " lifecycle events shown"),
    events.length ? el("ol", { class: "timeline" }, rows) :
      el("p", { class: "quiet" }, "No lifecycle events."));
}

function timelineDetail(event) {
  const data = event.data || {};
  if (event.kind === "net.connect" || event.kind === "net.request") return (data.host || "") + " · " + (data.verdict || "");
  if (event.kind === "child.start") return (data.cmd || []).join(" ").slice(0, 160);
  if (event.kind === "child.exit") return "Exit " + data.code + " after " + data.duration_s + "s";
  if (event.kind === "child.timeout") return "Execution exceeded its configured timeout";
  if (event.kind === "policy.compiled") return (data.backend || "sandbox") + " policy compiled";
  if (event.kind === "proxy.up") return "Local egress proxy listening on port " + data.port;
  if (event.kind === "mcp.broker.started") return data.registrations + " MCP definition(s) registered on an exact loopback port";
  if (event.kind === "mcp.broker.launch") return "Launched MCP principal " + (data.name || "unknown");
  if (event.kind === "mcp.broker.denied") return "MCP launch denied: " + (data.reason || "authorization failed");
  if (event.kind === "mcp.broker.stopped") return "Parent MCP broker stopped";
  if (event.kind === "session.start") return (data.policy || "policy") + (data.enforce ? " · enforcement requested" : " · observe mode");
  if (event.kind === "enforce.unavailable") return "Required enforcement backend was unavailable";
  if (event.kind === "env.allowed") return (data.names || []).length + " credential variable names available";
  if (event.kind === "env.scrubbed") return (data.count || 0) + " environment variables removed";
  if (event.kind === "deep.summary") return JSON.stringify(data);
  return "";
}

async function copyCommand(command) {
  try {
    await navigator.clipboard.writeText(command || "");
    foot.textContent = "Command copied to clipboard";
  } catch (_) {
    foot.textContent = "Clipboard permission denied";
  }
}

function exportJson(session) {
  const blob = new Blob([JSON.stringify(session, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = el("a", { href: url, download: "driftward-" + session.id + ".json" });
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Let the browser consume the Blob URL before releasing it. Immediate
  // revocation is flaky in WebKit and embedded browser shells.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  foot.textContent = "Session JSON exported";
}

function navigate(next) {
  view = next;
  currentSession = null;
  location.hash = next;
  setTabs(next);
  render();
}

async function render() {
  try {
    if (view === "overview") await renderOverview();
    else if (view === "behavior") await renderBehavior();
    else if (view === "sessions") await renderSessions();
    else if (view === "session" && currentSession) await openSession(currentSession);
  } catch (error) {
    app.replaceChildren(el("div", { class: "error-state" },
      el("strong", {}, "Dashboard data could not be loaded"),
      el("p", {}, error.message),
      el("button", { class: "button primary", onclick: render }, "Try again")));
    foot.textContent = "Dashboard unavailable";
  }
}

tabs.forEach(tab => tab.addEventListener("click", () => navigate(tab.dataset.view)));
window.addEventListener("hashchange", () => {
  const next = viewFromHash();
  if (next !== view) navigate(next);
});
live.addEventListener("change", scheduleRefresh);

function scheduleRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = live.checked ? setInterval(() => {
    if (!document.hidden) render();
  }, 10000) : null;
}

setTabs(view);
scheduleRefresh();
render();
