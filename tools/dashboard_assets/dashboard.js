let current = null;
let subscriptionStatus = null;
let allSessions = [];
let reportsLoaded = false;
let outputsLoaded = false;
let playbooksLoaded = false;
let refreshInFlight = false;
const VIEWS = ["sessionDetails", "reports", "outputs", "playbooks", "subscription"];
const SESSION_STORAGE_KEY = "utl.dashboard.selectedSessionId";
const DENSITY_STORAGE_KEY = "utl.dashboard.density";
const ACTIVE_VIEW_STORAGE_KEY = "utl.dashboard.activeView";

const DASH_TOKEN = new URLSearchParams(window.location.search).get("token") || "";

function _viewFromHash() {
  const raw = (window.location.hash || "").replace(/^#/, "");
  if (VIEWS.includes(raw)) return raw;
  return "sessionDetails";
}

function applyDensityMode(mode) {
  const useCompact = mode === "compact";
  document.body.classList.toggle("density-compact", useCompact);
  const densityBtn = document.getElementById("densityToggleBtn");
  if (densityBtn) {
    densityBtn.textContent = useCompact ? "Comfort mode" : "Compact mode";
    densityBtn.setAttribute("aria-pressed", useCompact ? "true" : "false");
  }
}

function initializeDensityMode() {
  const saved = sessionStorage.getItem(DENSITY_STORAGE_KEY);
  applyDensityMode(saved === "compact" ? "compact" : "comfortable");
}

function setGlobalStatus(message, isError = false) {
  const el = document.getElementById("globalStatus");
  if (!el) return;
  el.textContent = message;
  el.style.color = isError ? "#fca5a5" : "";
}

function setActiveView(viewName) {
  const target = VIEWS.includes(viewName) ? viewName : "sessionDetails";
  for (const name of VIEWS) {
    const section = document.getElementById(`view-${name}`);
    if (section) section.classList.toggle("active", name === target);
  }
  for (const link of document.querySelectorAll(".menu a[data-view]")) {
    const view = link.getAttribute("data-view");
    link.classList.toggle("active", view === target);
    link.setAttribute("aria-current", view === target ? "page" : "false");
  }
}

async function applyViewFromHash() {
  const target = _viewFromHash();
  setActiveView(target);
  sessionStorage.setItem(ACTIVE_VIEW_STORAGE_KEY, target);
  await ensureViewLoaded(target);
}

function esc(v) {
  return (v || "").toString().replace(/[&<>]/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[m]));
}

function stripAnsi(text) {
  return (text || "").replace(/\x1b\[[0-9;]*[A-Za-z]/g, "");
}

function decodeEscapedText(text) {
  let t = (text || "").toString();
  t = t.replace(/\r\n/g, "\n").replace(/\n/g, "\n").replace(/\t/g, "\t");
  t = t.replace(/\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  return stripAnsi(t);
}

function prettyMaybeJson(text) {
  const t = decodeEscapedText(text).trim();
  if (!t) return "";
  if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) {
    try {
      return JSON.stringify(JSON.parse(t), null, 2);
    } catch (_) {
      return t;
    }
  }
  return t;
}

function statusNote(message) {
  return `<p class="status-note">${esc(message)}</p>`;
}

function playbookRunPrompt(name) {
  return `run_playbook(name="${name}", target="<target>", variables_json="{\\"username\\":\\"user\\",\\"password\\":\\"pass\\"}")`;
}

function copyPlaybookRunPrompt(encodedName) {
  const name = decodeURIComponent(encodedName);
  const prompt = playbookRunPrompt(name);
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(prompt).then(
      () => alert("Copied AI run command for " + name),
      () => alert(prompt),
    );
    return;
  }
  alert(prompt);
}

function sessionCardMarkup(s) {
  const title = s.caption || s.id;
  const selected = current && s.id === current;
  return `<div class="card ${selected ? "is-selected" : ""}" data-id="${esc(s.id)}">
    <div><strong>${esc(title)}</strong></div>
    <div class="muted">${esc(s.id)}</div>
    <div class="muted">${esc(s.start)} to ${esc(s.end)}</div>
    <div class="muted">${Number(s.chat_turn_count || 0)} turns, ${Number(s.event_count || 0)} events, ${Number(s.report_count || 0)} reports</div>
  </div>`;
}

function renderSessionList() {
  const sessionsContainer = document.getElementById("sessions");
  if (!sessionsContainer) return;
  const filterInput = document.getElementById("sessionFilterInput");
  const query = filterInput ? String(filterInput.value || "").trim().toLowerCase() : "";
  let rows = allSessions;
  if (query) {
    rows = allSessions.filter(s => {
      const caption = String(s.caption || "").toLowerCase();
      const sid = String(s.id || "").toLowerCase();
      return caption.includes(query) || sid.includes(query);
    });
  }
  if (!rows.length) {
    sessionsContainer.innerHTML = statusNote(query ? "No sessions match your filter." : "No sessions found.");
    return;
  }
  sessionsContainer.innerHTML = rows.map(sessionCardMarkup).join("");
  for (const el of document.querySelectorAll("#sessions .card[data-id]")) {
    el.onclick = () => {
      const sid = el.getAttribute("data-id");
      if (!sid) return;
      if (_viewFromHash() !== "sessionDetails") window.location.hash = "#sessionDetails";
      loadSession(sid);
    };
  }
}

function setSessionDetailsExpansion(expanded) {
  const container = document.getElementById("sessionDetails");
  if (!container) return;
  for (const detail of container.querySelectorAll("details")) {
    detail.open = expanded;
  }
}

function renderSessionDetailToolbar() {
  return `<div class="detail-toolbar">
    <button type="button" onclick="setSessionDetailsExpansion(true)">Expand all</button>
    <button type="button" onclick="setSessionDetailsExpansion(false)">Collapse all</button>
  </div>`;
}

function renderCommandEvent(payload, eventType) {
  const cmdRaw = payload.command;
  const cmd = Array.isArray(cmdRaw) ? cmdRaw.join(" ") : (cmdRaw || "");
  const stdout = prettyMaybeJson(payload.stdout || "");
  const stderr = prettyMaybeJson(payload.stderr || "");
  const rc = payload.return_code ?? "";
  const ok = payload.success;
  const elapsed = payload.elapsed ?? payload.elapsed_seconds ?? "";

  let html = `<div class="event-meta">
    <span><span class="k">tool</span>: ${esc(payload.tool || "")}</span>
    <span><span class="k">success</span>: ${esc(String(ok))}</span>
    <span><span class="k">return_code</span>: ${esc(String(rc))}</span>
    <span><span class="k">elapsed</span>: ${esc(String(elapsed))}</span>
  </div>`;
  if (cmd) html += `<pre>${esc(cmd)}</pre>`;
  if (stdout) html += `<details><summary>stdout</summary><pre>${esc(stdout)}</pre></details>`;
  if (stderr) html += `<details><summary>stderr</summary><pre>${esc(stderr)}</pre></details>`;
  if (!cmd && !stdout && !stderr) html += `<pre>${esc(JSON.stringify(payload || {}, null, 2))}</pre>`;
  if (eventType === "command.invoke") {
    html += `<details><summary>raw payload</summary><pre>${esc(JSON.stringify(payload || {}, null, 2))}</pre></details>`;
  }
  return html;
}

function renderChatTurn(t) {
  const ts = t.timestamp || "";
  const turnId = t.turn_id || "";
  const userText = prettyMaybeJson(t.user_message || "");
  const assistantText = prettyMaybeJson(t.assistant_message || "");
  const toolCalls = JSON.stringify(t.tool_calls || [], null, 2);
  const metadata = JSON.stringify(t.metadata || {}, null, 2);
  const reports = Array.isArray(t.report_paths) ? t.report_paths : [];
  const reportLinks = reports.map(r => `<li><a href="#" onclick="viewFile('${encodeURIComponent(r)}');return false;">${esc(r)}</a></li>`).join("");

  return `<div class="card card--no-pointer">
    <div><strong>chat.turn</strong> <span class="muted">${esc(ts)}</span></div>
    <div class="muted">${esc(turnId)}</div>
    ${userText ? `<details><summary>user_message</summary><pre>${esc(userText)}</pre></details>` : ""}
    ${assistantText ? `<details><summary>assistant_message</summary><pre>${esc(assistantText)}</pre></details>` : ""}
    <details><summary>tool_calls</summary><pre>${esc(toolCalls)}</pre></details>
    <details><summary>metadata</summary><pre>${esc(metadata)}</pre></details>
    <details ${reportLinks ? "" : "open"}><summary>report_paths</summary><ul>${reportLinks || "<li class='muted'>No reports linked</li>"}</ul></details>
  </div>`;
}

function summarizeFlowStepPayload(eventType, payload) {
  if (eventType === "tool.invoke") {
    return `<div class="event-meta">
      <span><span class="k">tool</span>: ${esc(payload.tool || "")}</span>
      <span><span class="k">session_id</span>: ${esc(payload.session_id || payload.event_session_id || payload.main_session_id || "")}</span>
    </div>`;
  }
  if (eventType === "tool.result") {
    return `<div class="event-meta">
      <span><span class="k">tool</span>: ${esc(payload.tool || "")}</span>
      <span><span class="k">success</span>: ${esc(String(payload.success))}</span>
      <span><span class="k">session_id</span>: ${esc(payload.session_id || payload.event_session_id || payload.main_session_id || "")}</span>
    </div><details><summary>raw payload</summary><pre>${esc(JSON.stringify(payload || {}, null, 2))}</pre></details>`;
  }
  return renderCommandEvent(payload || {}, eventType || "");
}

function renderFlowGroup(flow, index) {
  const steps = Array.isArray(flow.steps) ? flow.steps : [];
  const stepsHtml = steps.map((step, stepIndex) => {
    const et = step.event_type || "";
    return `<div class="flow-step">
      <div class="flow-step-title"><strong>Step ${stepIndex + 1}: ${esc(et)}</strong> <span class="muted">${esc(step.timestamp || "")}</span></div>
      ${summarizeFlowStepPayload(et, step.payload || {})}
    </div>`;
  }).join("");

  const title = flow.tool ? `${flow.tool}` : `Flow ${index + 1}`;
  return `<details class="card card--no-pointer">
    <summary><strong>${esc(title)}</strong> <span class="muted">${esc(flow.session_id || "")} | ${esc(flow.start || "")} to ${esc(flow.end || "")}</span></summary>
    ${stepsHtml || statusNote("No flow steps.")}
  </details>`;
}

function renderInvalidFlowGroup(group, index) {
  const sequence = Array.isArray(group.event_types) ? group.event_types.join(" -> ") : "";
  const events = Array.isArray(group.events) ? group.events : [];
  const rawEvents = events.map((event) => `${event.timestamp || ""} ${event.event_type || ""}`).join("\n");
  return `<details class="card card--no-pointer">
    <summary><strong>Excluded ${index + 1}</strong> <span class="muted">${esc(group.session_id || "")} | ${esc(group.reason || "")}</span></summary>
    <div class="event-meta">
      <span><span class="k">event_count</span>: ${esc(String(group.event_count ?? events.length))}</span>
      <span><span class="k">sequence</span>: ${esc(sequence)}</span>
    </div>
    <details><summary>raw sequence</summary><pre>${esc(rawEvents)}</pre></details>
  </details>`;
}

function withToken(path) {
  if (!DASH_TOKEN) return path;
  return path + (path.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(DASH_TOKEN);
}

async function apiFetch(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (DASH_TOKEN && !headers.Authorization) headers.Authorization = "Bearer " + DASH_TOKEN;
  const res = await fetch(withToken(path), { ...options, headers });
  if (res.status === 401) {
    throw new Error("Unauthorized: provide dashboard token using ?token=YOUR_TOKEN");
  }
  return res;
}

async function parseApiJson(res) {
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_) {
    data = { detail: text };
  }
  if (!res.ok) {
    throw new Error(data.detail || data.error || `Request failed (${res.status})`);
  }
  return data;
}

function subscriptionBannerClass(status) {
  if (!status) return "sub-banner sub-banner-info";
  const state = (status.state || "").toLowerCase();
  if (state === "active") return status.expiring_soon ? "sub-banner sub-banner-warn" : "sub-banner sub-banner-ok";
  if (state === "missing" || state === "expired" || state === "invalid" || state === "not_started") return "sub-banner sub-banner-error";
  return "sub-banner sub-banner-info";
}

function subscriptionExpiryBadge(status) {
  if (!status) return "";
  const state = (status.state || "").toLowerCase();
  const days = status.expires_in_days;
  if (state === "expired") return '<span class="expiry-badge expiry-badge-error">Expired</span>';
  if (state !== "active" || days === null || days === undefined || Number.isNaN(Number(days))) return "";
  const dayCount = Number(days);
  if (dayCount <= 0) return '<span class="expiry-badge expiry-badge-error">Expires today</span>';
  if (dayCount <= 3) return `<span class="expiry-badge expiry-badge-error">${esc(String(dayCount))} day${dayCount === 1 ? "" : "s"} left</span>`;
  if (status.expiring_soon) return `<span class="expiry-badge expiry-badge-warn">${esc(String(dayCount))} day${dayCount === 1 ? "" : "s"} left</span>`;
  return `<span class="expiry-badge expiry-badge-ok">${esc(String(dayCount))} day${dayCount === 1 ? "" : "s"} left</span>`;
}

function renderSubscriptionBanner(status) {
  const el = document.getElementById("subscriptionBanner");
  if (!el) return;
  if (!status) {
    el.className = "sub-banner sub-banner-info";
    el.textContent = "Subscription status unavailable.";
    return;
  }
  el.className = subscriptionBannerClass(status);
  const msg = esc(status.message || "Subscription state unavailable");
  const subscriber = esc(status.subscriber_name || "N/A");
  const endDate = esc(status.subscription_end_date || "N/A");
  const badge = subscriptionExpiryBadge(status);
  const details = `<div class="meta">State: ${esc(status.state || "unknown")} | Subscriber: ${subscriber} | End: ${endDate} | Trust: ${esc(status.trust_mode || "unknown")} | Override Active: ${esc(String(!!status.key_override_active))}</div>`;
  el.innerHTML = `<div class="sub-banner-head"><strong>Subscription Status:</strong> ${msg}${badge}</div>${details}`;
}

function renderSubscriptionPanel(status) {
  const panel = document.getElementById("subscriptionPanel");
  if (!panel) return;
  const s = status || {};
  const className = subscriptionBannerClass(s);
  const badge = subscriptionExpiryBadge(s);
  const expires = s.expires_in_days === null || s.expires_in_days === undefined ? "N/A" : String(s.expires_in_days);
  panel.innerHTML = `
    <div class="${className}">
      <div class="sub-banner-head"><strong>${esc((s.state || "unknown").toUpperCase())}</strong> - ${esc(s.message || "No status available")}${badge}</div>
      <div class="meta">Code: ${esc(s.code || "n/a")} | Checked: ${esc(s.checked_at || "n/a")}</div>
    </div>
    <div class="subscription-grid">
      <div class="subscription-kv"><div class="label">Subscriber Name</div><div class="value">${esc(s.subscriber_name || "N/A")}</div></div>
      <div class="subscription-kv"><div class="label">Start Date</div><div class="value">${esc(s.subscription_start_date || "N/A")}</div></div>
      <div class="subscription-kv"><div class="label">End Date</div><div class="value">${esc(s.subscription_end_date || "N/A")}</div></div>
      <div class="subscription-kv"><div class="label">Days Remaining</div><div class="value">${esc(expires)} ${badge}</div></div>
      <div class="subscription-kv"><div class="label">License Path</div><div class="value">${esc(s.license_path || "N/A")}</div></div>
      <div class="subscription-kv"><div class="label">Trust Mode</div><div class="value">${esc(s.trust_mode || "N/A")}</div></div>
      <div class="subscription-kv"><div class="label">Key Override Active</div><div class="value">${esc(String(!!s.key_override_active))}</div></div>
    </div>
    <div class="card card--no-pointer">
      <div><strong>Upload New subscription.lic</strong></div>
      <div class="row" style="margin-top:8px;">
        <input id="subscriptionFileInput" type="file" accept=".lic,application/json" />
        <button id="subscriptionUploadBtn" onclick="uploadSubscriptionLicense()">Upload License</button>
      </div>
      <div class="muted upload-help">Upload a signed .lic file. Any .lic filename is accepted and saved as subscription.lic. MCP tool execution is blocked when the subscription is missing, invalid, not started, or expired.</div>
      <pre id="subscriptionUploadStatus" class="muted"></pre>
    </div>
  `;
}

async function loadSubscriptionStatus() {
  setGlobalStatus("Refreshing subscription...");
  const res = await apiFetch("/api/subscription/status");
  const data = await parseApiJson(res);
  subscriptionStatus = data.subscription || null;
  renderSubscriptionBanner(subscriptionStatus);
  renderSubscriptionPanel(subscriptionStatus);
  setGlobalStatus("Ready");
}

async function uploadSubscriptionLicense() {
  const input = document.getElementById("subscriptionFileInput");
  const statusEl = document.getElementById("subscriptionUploadStatus");
  const button = document.getElementById("subscriptionUploadBtn");
  const file = input && input.files && input.files[0];
  if (!file) {
    if (statusEl) statusEl.textContent = "Please select a .lic file first.";
    return;
  }
  if (button) button.disabled = true;
  if (statusEl) statusEl.textContent = "Uploading...";
  try {
    const headers = {
      "Content-Type": "application/octet-stream",
      "X-Subscription-Filename": file.name || "subscription.lic",
    };
    const res = await apiFetch("/api/subscription/upload", {
      method: "POST",
      headers,
      body: await file.arrayBuffer(),
    });
    const payload = await parseApiJson(res);
    if (payload.success === false) throw new Error(payload.detail || payload.error || "Upload failed");
    if (statusEl) statusEl.textContent = "Upload completed successfully.";
    await loadSubscriptionStatus();
  } catch (err) {
    if (statusEl) statusEl.textContent = err.message || String(err);
  } finally {
    if (button) button.disabled = false;
  }
}

async function loadSessions() {
  setGlobalStatus("Refreshing sessions...");
  const sessionsEl = document.getElementById("sessions");
  if (sessionsEl) sessionsEl.innerHTML = statusNote("Loading sessions...");
  const res = await apiFetch("/api/sessions");
  const data = await parseApiJson(res);
  allSessions = Array.isArray(data.sessions) ? data.sessions : [];
  const summary = document.getElementById("sessionSummary");
  if (summary) {
    summary.textContent = `${allSessions.length} sessions | ${data.generated_at || "n/a"} | log: ${data.audit_log_path || "n/a"}`;
  }
  renderSessionList();

  const savedSession = sessionStorage.getItem(SESSION_STORAGE_KEY);
  if (!current && savedSession && allSessions.some(s => s.id === savedSession)) current = savedSession;
  if (!current && allSessions.length) current = allSessions[0].id;
  if (current) await loadSession(current);
  setGlobalStatus("Ready");
}

async function loadSession(id) {
  current = id;
  sessionStorage.setItem(SESSION_STORAGE_KEY, id);
  renderSessionList();
  const container = document.getElementById("sessionDetails");
  if (container) container.innerHTML = statusNote("Loading session details...");

  const res = await apiFetch("/api/sessions/" + encodeURIComponent(id));
  const data = await parseApiJson(res);
  if (!data.success) {
    if (container) container.textContent = data.error || "Unable to load session";
    return;
  }

  const s = data.session;
  const turnsHtml = (s.chat_turns || []).map(renderChatTurn).join("");
  const validFlows = (s.flow_groups && Array.isArray(s.flow_groups.valid)) ? s.flow_groups.valid : [];
  const invalidFlows = (s.flow_groups && Array.isArray(s.flow_groups.invalid)) ? s.flow_groups.invalid : [];
  const flowsHtml = validFlows.map(renderFlowGroup).join("");
  const invalidHtml = invalidFlows.map(renderInvalidFlowGroup).join("");
  const toolPills = (s.tools || []).map(t => `<span class="pill">${esc(t)}</span>`).join("");
  const reportLinks = (s.reports || []).map(r => `<li><a href="#" onclick="viewFile('${encodeURIComponent(r)}');return false;">${esc(r)}</a></li>`).join("");

  if (!container) return;
  container.innerHTML = `
    ${renderSessionDetailToolbar()}
    <div class="card card--no-pointer">
      <div><strong>${esc(s.caption || s.id)}</strong></div>
      <div class="muted">${esc(s.id)}</div>
      <div class="muted">${esc(s.start)} to ${esc(s.end)} | ${s.chat_turns?.length || 0} turns | ${s.event_count} events</div>
      <div>${toolPills || '<span class="muted">No tool names extracted</span>'}</div>
      <div><strong>Session Reports</strong><ul>${reportLinks || "<li class='muted'>No linked reports</li>"}</ul></div>
    </div>
    <h3>Chat Turns</h3>
    ${turnsHtml || statusNote("No chat turns saved.")}
    <h3>Tool & Command Flows</h3>
    ${flowsHtml || statusNote("No conforming 4-step flows found.")}
    <details class="invalid-list">
      <summary>Excluded/Invalid Groups (${invalidFlows.length})</summary>
      ${invalidHtml || statusNote("No excluded groups.")}
    </details>
  `;
}

function capNotice(total, cap) {
  if (total <= cap) return "";
  return statusNote(`Showing first ${cap} of ${total} items.`);
}

async function loadReports() {
  setGlobalStatus("Loading reports...");
  const target = document.getElementById("reports");
  if (target) target.innerHTML = statusNote("Loading reports...");
  const res = await apiFetch("/api/reports");
  const data = await parseApiJson(res);
  const all = Array.isArray(data.reports) ? data.reports : [];
  const rows = all.slice(0, 200).map(r => `
    <div class="card card--no-pointer">
      <div><a href="#" onclick="viewFile('${encodeURIComponent(r.path)}');return false;">${esc(r.relative_path)}</a></div>
      <div class="muted">${esc(r.modified)} | ${r.size_bytes} bytes</div>
    </div>
  `).join("");
  if (target) {
    target.innerHTML = capNotice(all.length, 200) + (rows || statusNote("No reports found."));
  }
  setGlobalStatus("Ready");
}

async function loadOutputs() {
  setGlobalStatus("Loading output files...");
  const target = document.getElementById("outputs");
  if (target) target.innerHTML = statusNote("Loading output files...");
  const res = await apiFetch("/api/output-files");
  const data = await parseApiJson(res);
  const all = Array.isArray(data.files) ? data.files : [];
  const rows = all.slice(0, 200).map(r => `
    <div class="card card--no-pointer">
      <div><a href="#" onclick="viewFile('${encodeURIComponent(r.path)}');return false;">${esc(r.relative_path)}</a></div>
      <div class="muted">${esc(r.modified)} | ${r.size_bytes} bytes</div>
    </div>
  `).join("");
  if (target) {
    target.innerHTML = capNotice(all.length, 200) + (rows || statusNote("No output files found."));
  }
  setGlobalStatus("Ready");
}

async function loadPlaybooks() {
  setGlobalStatus("Loading playbooks...");
  const target = document.getElementById("playbooks");
  if (target) target.innerHTML = statusNote("Loading playbooks...");
  const res = await apiFetch("/api/playbooks");
  const data = await parseApiJson(res);
  const rows = (data.playbooks || []).map(p => `
    <div class="card card--no-pointer">
      <div><strong>${esc(p.name)}</strong> <span class="muted">v${esc(String(p.version || 0))}</span></div>
      <div class="muted">${esc((p.tags || []).join(", "))}</div>
      <div class="row" style="margin-top:8px;">
        <button onclick="openPlaybook('${encodeURIComponent(p.name)}')">Edit</button>
        <button onclick="clonePlaybook('${encodeURIComponent(p.name)}')">Clone</button>
        <button onclick="copyPlaybookRunPrompt('${encodeURIComponent(p.name)}')">Copy AI Run Prompt</button>
        <button onclick="deletePlaybookPrompt('${encodeURIComponent(p.name)}')">Delete</button>
      </div>
      <div class="muted" style="margin-top:8px;">Run from AI chat: <code>${esc(playbookRunPrompt(p.name))}</code></div>
      ${(p.errors || []).length ? `<details><summary>validation errors</summary><pre>${esc((p.errors || []).join("\n"))}</pre></details>` : ""}
    </div>
  `).join("");
  const createForm = `
    <div class="card card--no-pointer">
      <div><strong>Create/Update Playbook</strong></div>
      <div class="muted" style="margin-top:4px;">Store path: ${esc(data.playbooks_dir || "n/a")}</div>
      <div class="row" style="margin-top:8px;">
        <input id="pbName" placeholder="playbook_name" style="min-width:220px;" />
      </div>
      <textarea id="pbYaml" rows="18" style="width:100%;margin-top:8px;" placeholder="Paste YAML playbook here"></textarea>
      <div class="row" style="margin-top:8px;">
        <button onclick="validatePlaybookDraft()">Validate</button>
        <button onclick="savePlaybookDraft()">Save</button>
      </div>
      <pre id="pbValidation" class="muted"></pre>
    </div>
  `;
  if (target) target.innerHTML = createForm + (rows || statusNote("No playbooks found."));
  setGlobalStatus("Ready");
}

async function ensureViewLoaded(viewName) {
  if (viewName === "reports" && !reportsLoaded) {
    await loadReports();
    reportsLoaded = true;
  }
  if (viewName === "outputs" && !outputsLoaded) {
    await loadOutputs();
    outputsLoaded = true;
  }
  if (viewName === "playbooks" && !playbooksLoaded) {
    await loadPlaybooks();
    playbooksLoaded = true;
  }
}

async function openPlaybook(encodedName) {
  const name = decodeURIComponent(encodedName);
  const res = await apiFetch("/api/playbooks/" + encodeURIComponent(name));
  const data = await parseApiJson(res);
  if (!data.success) return alert(data.error || "Failed to load playbook");
  const nameEl = document.getElementById("pbName");
  const yamlEl = document.getElementById("pbYaml");
  if (nameEl) nameEl.value = name;
  if (yamlEl) yamlEl.value = data.yaml || "";
}

async function validatePlaybookDraft() {
  const name = (document.getElementById("pbName") || {}).value || "";
  const content = (document.getElementById("pbYaml") || {}).value || "";
  const res = await apiFetch("/api/playbooks/" + encodeURIComponent(name || "draft") + "/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content }),
  });
  const data = await parseApiJson(res);
  const out = document.getElementById("pbValidation");
  if (out) out.textContent = JSON.stringify(data, null, 2);
}

async function savePlaybookDraft() {
  const name = (document.getElementById("pbName") || {}).value || "";
  const content = (document.getElementById("pbYaml") || {}).value || "";
  if (!name || !content) return alert("name and yaml are required");
  const res = await apiFetch("/api/playbooks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, content }),
  });
  const data = await parseApiJson(res);
  const out = document.getElementById("pbValidation");
  if (out) out.textContent = JSON.stringify(data, null, 2);
  await loadPlaybooks();
}

async function clonePlaybook(encodedName) {
  const name = decodeURIComponent(encodedName);
  const target = prompt("Clone to new name:", name + "_copy");
  if (!target) return;
  const res = await apiFetch("/api/playbooks/" + encodeURIComponent(name) + "/clone", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_name: target }),
  });
  const data = await parseApiJson(res);
  if (!data.success) alert(data.error || "Clone failed");
  await loadPlaybooks();
}

async function deletePlaybookPrompt(encodedName) {
  const name = decodeURIComponent(encodedName);
  if (!confirm("Delete " + name + "?")) return;
  const res = await apiFetch("/api/playbooks/" + encodeURIComponent(name), { method: "DELETE" });
  const data = await parseApiJson(res);
  if (!data.success) alert(data.error || "Delete failed");
  await loadPlaybooks();
}

async function viewFile(encodedPath) {
  const target = withToken("/file/view?path=" + encodedPath);
  window.open(target, "_blank");
}

async function refreshAllData() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  const refreshBtn = document.getElementById("refreshBtn");
  if (refreshBtn) {
    refreshBtn.disabled = true;
    refreshBtn.textContent = "Refreshing...";
  }
  try {
    reportsLoaded = false;
    outputsLoaded = false;
    playbooksLoaded = false;
    await loadSubscriptionStatus();
    await loadSessions();
    await ensureViewLoaded(_viewFromHash());
  } finally {
    refreshInFlight = false;
    if (refreshBtn) {
      refreshBtn.disabled = false;
      refreshBtn.textContent = "Refresh";
    }
  }
}

document.getElementById("refreshBtn").onclick = async () => {
  try {
    await refreshAllData();
  } catch (err) {
    setGlobalStatus("Refresh failed", true);
    alert(err.message || String(err));
  }
};

const densityToggleBtn = document.getElementById("densityToggleBtn");
if (densityToggleBtn) {
  densityToggleBtn.addEventListener("click", () => {
    const isCompact = document.body.classList.contains("density-compact");
    const nextMode = isCompact ? "comfortable" : "compact";
    sessionStorage.setItem(DENSITY_STORAGE_KEY, nextMode);
    applyDensityMode(nextMode);
  });
}

const sessionFilterInput = document.getElementById("sessionFilterInput");
if (sessionFilterInput) {
  let filterTimer = null;
  sessionFilterInput.addEventListener("input", () => {
    if (filterTimer) window.clearTimeout(filterTimer);
    filterTimer = window.setTimeout(() => {
      renderSessionList();
    }, 120);
  });
}

for (const link of document.querySelectorAll(".menu a[data-view]")) {
  link.addEventListener("keydown", (event) => {
    if (!["ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) return;
    const links = Array.from(document.querySelectorAll(".menu a[data-view]"));
    const index = links.indexOf(event.currentTarget);
    if (index < 0) return;
    event.preventDefault();
    let nextIndex = index;
    if (event.key === "ArrowRight") nextIndex = (index + 1) % links.length;
    if (event.key === "ArrowLeft") nextIndex = (index - 1 + links.length) % links.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = links.length - 1;
    const nextLink = links[nextIndex];
    if (nextLink) {
      nextLink.focus();
      nextLink.click();
    }
  });
}

(async () => {
  initializeDensityMode();
  if (!_viewFromHash() || !window.location.hash) {
    const savedView = sessionStorage.getItem(ACTIVE_VIEW_STORAGE_KEY);
    if (savedView && VIEWS.includes(savedView)) {
      window.location.hash = `#${savedView}`;
    } else {
      window.location.hash = "#sessionDetails";
    }
  }
  window.addEventListener("hashchange", async () => {
    try {
      await applyViewFromHash();
    } catch (err) {
      setGlobalStatus("Navigation load failed", true);
      const target = document.getElementById("sessionDetails");
      if (target) target.textContent = err.message || String(err);
    }
  });

  try {
    await loadSubscriptionStatus();
    await loadSessions();
    await applyViewFromHash();
  } catch (err) {
    setGlobalStatus("Initial load failed", true);
    const target = document.getElementById("sessionDetails");
    if (target) target.textContent = err.message || String(err);
  }
})();
