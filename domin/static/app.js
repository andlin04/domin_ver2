"use strict";
// domin front end: theme, tables, scan jobs, charts (Chart.js) and the tools page. No inline scripts (CSP).

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const pageData = () => { const el = $("#page-data"); return el ? JSON.parse(el.textContent) : {}; };

// --- theme ---------------------------------------------------------------------------------------------------------
$("#theme")?.addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("domin-theme", next); } catch (e) { /* not saved */ }
  location.reload();   // charts read their colours at creation
});

// --- go to domain --------------------------------------------------------------------------------------------------
const jump = $("[data-jump]");
const goDomain = (v) => { v = v.trim().toLowerCase(); if (v) location.href = "/d/" + encodeURIComponent(v); };
jump?.addEventListener("submit", (ev) => { ev.preventDefault(); goDomain(jump.q.value); });
// Picking a suggestion goes straight away (Chromium: insertReplacementText, Firefox: no inputType); typing does not.
jump?.q.addEventListener("input", (ev) => {
  if (ev.inputType && ev.inputType !== "insertReplacementText") return;
  const list = $("#domain-list");
  if (list && [...list.options].some((o) => o.value === jump.q.value)) goDomain(jump.q.value);
});
// Pages without the overview's list load the names on first focus.
jump?.q.addEventListener("focus", () => {
  if ($("#domain-list")) return;
  const list = document.createElement("datalist");
  list.id = "domain-list";
  document.body.append(list);
  fetch("/api/domains").then((r) => r.json()).then((rows) => {
    list.append(...rows.map((d) => Object.assign(document.createElement("option"), { value: d.name })));
  }).catch((e) => console.error("domain list", e));
}, { once: true });
// "/" focuses the box from anywhere except a text field.
document.addEventListener("keydown", (ev) => {
  if (ev.key !== "/" || !jump || ev.ctrlKey || ev.metaKey || ev.altKey) return;
  if (ev.target.closest("input, textarea, select, [contenteditable]")) return;
  ev.preventDefault();
  jump.q.focus();
});

// --- tables: sort, filter, row links -------------------------------------------------------------------------------
const ipKey = (s) => s.includes(".") ? s.split(".").map((n) => n.padStart(3, "0")).join(".") : s;
$$("table.sortable").forEach((table) => {
  $$("th[data-sort]", table).forEach((th, col) => th.addEventListener("click", () => {
    const type = th.dataset.sort;
    const dir = th.dataset.dir === "asc" ? "desc" : "asc";
    $$("th", table).forEach((h) => delete h.dataset.dir);
    th.dataset.dir = dir;
    const body = table.tBodies[0];
    const key = (tr) => {
      const t = tr.cells[col].textContent.trim();
      if (type === "num") return parseFloat(t) || 0;
      return type === "ip" ? ipKey(t) : t.toLowerCase();
    };
    const rows = [...body.rows].sort((a, b) => (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0) * (dir === "asc" ? 1 : -1));
    body.append(...rows);
  }));
});
document.addEventListener("click", (ev) => { if (ev.target.closest("th .colf")) ev.stopPropagation(); }, true);
// the Filter box (all words, anywhere in the row) and a box per column (text in that column) add up
function applyFilters(table) {
  const words = ($(`[data-filter="#${table.id}"]`)?.value || "").toLowerCase().split(/\s+/).filter(Boolean);
  const cols = $$("thead th", table).map((th) => ($(".colf", th)?.value || "").trim().toLowerCase());
  const start = $$("thead th", table).map((th) => th.dataset.match === "start");   // EU: "eu" isn't "Non-EU"
  const cell = (tr, i) => (tr.cells[i]?.textContent || "").trim().toLowerCase();
  const has = (v, t, i) => (start[i] ? v.startsWith(t) : v.includes(t));
  const ok = (c, v, i) => c[0] === "!" ? !c.slice(1) || !has(v, c.slice(1), i) : has(v, c, i);   // "!text": without it
  for (const tr of table.tBodies[0].rows) {
    const text = tr.textContent.toLowerCase();
    tr.hidden = !words.every((w) => text.includes(w)) || !cols.every((c, i) => !c || ok(c, cell(tr, i), i));
  }
}
$$("table[data-colfilters]").forEach((table) => {
  $$("thead th", table).forEach((th) => {
    const input = document.createElement("input");
    input.className = "colf";
    input.placeholder = "Filter";
    input.autocomplete = "off";
    input.setAttribute("aria-label", `Filter ${th.textContent.trim()}`);
    input.addEventListener("input", () => applyFilters(table));
    th.append(input);
  });
});
$$("[data-filter]").forEach((input) => input.addEventListener("input", () => applyFilters($(input.dataset.filter))));
// search page: empty boxes stay out of the address
$("#search-form")?.addEventListener("formdata", (ev) => {
  for (const [k, v] of [...ev.formData]) if (!v && k !== "q") ev.formData.delete(k);
});
// tabbed cards: one panel shown; the choice is kept in the address (#drill)
$$("[data-tabs]").forEach((card) => {
  const show = (name) => {
    $$("[data-tab]", card).forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    $$("[data-panel]", card).forEach((p) => { p.hidden = p.dataset.panel !== name; });
  };
  $$("[data-tab]", card).forEach((b) => b.addEventListener("click", () => {
    show(b.dataset.tab);
    history.replaceState(null, "", b.dataset.tab === "drill" ? "#drill" : location.pathname);
  }));
  if (location.hash === "#drill") show("drill");
});
// sideways overflow: a fade and a "More columns" button while columns are hidden to the right
$$(".table-wrap").forEach((wrap) => {
  const box = document.createElement("div");
  box.className = "table-scroll";
  wrap.before(box);
  box.append(wrap);
  const hint = document.createElement("button");
  hint.type = "button";
  hint.className = "scroll-hint";
  hint.textContent = "More columns →";
  hint.addEventListener("click", () => wrap.scrollBy({ left: wrap.clientWidth * 0.7, behavior: "smooth" }));
  box.after(hint);
  const update = () => {
    box.classList.toggle("more-right", wrap.scrollLeft + wrap.clientWidth < wrap.scrollWidth - 2);
    wrap.classList.toggle("scrolled-x", wrap.scrollLeft > 0);
  };
  wrap.addEventListener("scroll", update, { passive: true });
  if (window.ResizeObserver) new ResizeObserver(update).observe(wrap);
  update();
});
document.addEventListener("click", (ev) => {
  const tr = ev.target.closest("tr[data-href]");
  if (tr && !ev.target.closest("a")) location.href = tr.dataset.href;
});

// --- scans ---------------------------------------------------------------------------------------------------------
function describe(job) {
  if (job.status === "queued") return `Queued${job.ahead ? ` (${job.ahead} ahead)` : ""}…`;
  if (job.status === "running") return `Scanning ${job.domain}: ${job.progress || "starting"}…`;
  if (job.status === "failed") return `Scan failed: ${job.error || "unknown error"}`;
  if (job.status === "cancelled") return "The scan was cancelled";
  return "Done";
}
async function follow(jobId, status, button) {
  status.hidden = false;
  for (;;) {
    let job;
    try {
      const r = await fetch(`/api/jobs/${jobId}`);
      job = await r.json();
      if (!r.ok) throw new Error(job.error || r.status);
    } catch (e) {
      status.textContent = "Lost contact with the server, retrying…";
      await new Promise((ok) => setTimeout(ok, 5000));
      continue;
    }
    status.textContent = describe(job);
    if (job.status === "done") { location.href = `/d/${job.domain}?scan=${job.scan_id}`; return; }
    if (job.status === "failed" || job.status === "cancelled") { if (button) button.disabled = false; return; }
    await new Promise((ok) => setTimeout(ok, 2000));
  }
}
$$("[data-scan-form]").forEach((form) => {
  const status = $("[data-scan-status]", form);
  const button = $("button", form);
  if (status.dataset.job) { button.disabled = true; follow(status.dataset.job, status, button); }
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    button.disabled = true;
    status.hidden = false;
    status.textContent = "Queuing…";
    try {
      const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" },
                                            body: JSON.stringify({ domain: form.domain.value }) });
      const job = await r.json();
      if (!r.ok) throw new Error(job.error || `HTTP ${r.status}`);
      follow(job.id, status, button);
    } catch (e) {
      status.textContent = e.message;
      button.disabled = false;
    }
  });
});
$("[data-scan-select]")?.addEventListener("change", (ev) => {
  location.href = `${location.pathname}?scan=${ev.target.value}`;
});

// --- charts --------------------------------------------------------------------------------------------------------
const palette = () => [css("--accent"), css("--accent-2"), "#f59e0b", "#ef4444", "#8b5cf6", "#10b981", "#3b82f6",
  "#ec4899", "#14b8a6", "#f97316", "#64748b"];
function chartDefaults() {
  if (!window.Chart) return false;
  Chart.defaults.color = css("--muted");
  Chart.defaults.borderColor = css("--border");
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.plugins.legend.labels.boxWidth = 12;
  Chart.defaults.maintainAspectRatio = false;
  return true;
}
function hbar(id, all, label, onClick) {
  const el = document.getElementById(id);
  const rows = (all || []).filter((r) => r.label !== "Other");   // a long tail folded into one bar dwarfs the top ones
  if (!el || !rows.length) { if (el) el.parentElement.innerHTML = '<p class="muted">No data</p>'; return; }
  const other = (all || []).find((r) => r.label === "Other");
  if (other) el.closest(".card").querySelector("h2 small")?.append(` · ${other.ips.toLocaleString()} more in the rest`);
  new Chart(el, {
    type: "bar",
    data: { labels: rows.map((r) => r.label), datasets: [{ label, data: rows.map((r) => r.ips), backgroundColor: css("--accent"), borderRadius: 6, maxBarThickness: 28 }] },
    options: { indexAxis: "y", plugins: { legend: { display: false },
               tooltip: { callbacks: { afterLabel: (c) => rows[c.dataIndex].domains ? `${rows[c.dataIndex].domains} domains` : "" } } },
               scales: { x: { beginAtZero: true, grid: { display: false } }, y: { grid: { display: false } } }, onClick },
  });
}
function doughnut(id, rows) {
  const el = document.getElementById(id);
  if (!el || !rows?.length) { if (el) el.parentElement.innerHTML = '<p class="muted">No addresses</p>'; return; }
  new Chart(el, {
    type: "doughnut",
    data: { labels: rows.map((r) => r.label), datasets: [{ data: rows.map((r) => r.ips), backgroundColor: palette(), borderWidth: 0 }] },
    options: { cutout: "62%", plugins: { legend: { position: "right" } } },
  });
}

function allCharts() {
  // a click on a bar sets that column's filter box to the bar's value and runs the search
  const d = pageData();
  for (const id of ["countries", "netnames", "asns"]) {
    hbar(id, d[id], "Addresses", (ev, els) => {   // labels read at the click: drill.js redraws the bars
      const canvas = document.getElementById(id);
      const box = $(`[name="f_${canvas.dataset.col}"]`);
      if (!els.length || !box) return;
      box.value = Chart.getChart(canvas).data.labels[els[0].index];
      $("#search-form").requestSubmit();
    });
  }
}

function overviewCharts() {
  const d = pageData();
  new Chart($("#perDay"), {
    type: "bar",
    data: { labels: d.per_day.map((r) => r.day),
            datasets: [{ label: "Scans", data: d.per_day.map((r) => r.scans), backgroundColor: css("--accent"), borderRadius: 4 }] },
    options: { plugins: { legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 12 } }, y: { beginAtZero: true } } },
  });
  hbar("countries", d.countries, "Addresses");
  hbar("netnames", d.netnames, "Addresses");
  euLine(d.eu?.map((r) => r.day), d.eu?.map((r) => r.pct));
}

function euLine(labels, values, onClick) {
  const el = $("#eu");
  if (!el || !values?.some((v) => v !== null)) { if (el) el.parentElement.innerHTML = '<p class="muted">No addresses with a country</p>'; return; }
  new Chart(el, {
    type: "line",
    data: { labels, datasets: [{ label: "In the EU", data: values, borderColor: css("--accent"), backgroundColor: css("--accent"),
            tension: .25, spanGaps: true, pointRadius: values.length > 60 ? 0 : 2.5 }] },
    options: { plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => `In the EU: ${c.raw} %` } } },
               scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 12 } }, y: { min: 0, max: 100, ticks: { callback: (v) => `${v} %` } } },
               onClick },
  });
}

function domainCharts() {
  const d = pageData();
  const h = d.history;
  const series = [["hosts", "Host names", css("--accent")], ["resolved", "Resolving", css("--accent-2")],
                  ["ips", "Addresses", "#f59e0b"], ["asns", "ASNs", "#ec4899"]];
  const current = h.findIndex((s) => s.id === d.current);
  new Chart($("#history"), {
    type: "line",
    data: { labels: h.map((s) => s.started.slice(0, 10)),
            datasets: series.map(([k, label, color]) => ({ label, data: h.map((s) => s[k]), borderColor: color, backgroundColor: color,
              tension: .25, pointRadius: h.map((_, i) => (i === current ? 6 : h.length > 60 ? 0 : 2.5)), pointHoverRadius: 6, yAxisID: k === "asns" ? "y2" : "y" })) },
    options: { interaction: { mode: "index", intersect: false },
               scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 12 } }, y: { beginAtZero: true },
                         y2: { beginAtZero: true, position: "right", grid: { display: false }, title: { display: true, text: "ASNs" } } },
               onClick: (_, els) => { if (els.length) location.href = `${location.pathname}?scan=${h[els[0].index].id}`; } },
  });
  if (d.churn?.length && $("#churn")) {
    new Chart($("#churn"), {
      type: "bar",
      data: { labels: d.churn.map((c) => c.started.slice(0, 10)),
              datasets: [{ label: "Added", data: d.churn.map((c) => c.added), backgroundColor: css("--up"), borderRadius: 4 },
                         { label: "Removed", data: d.churn.map((c) => -c.removed), backgroundColor: css("--down"), borderRadius: 4 }] },
      options: { scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 12 } }, y: { stacked: true, ticks: { callback: (v) => Math.abs(v) } } },
                 plugins: { tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${Math.abs(c.raw)}` } } },
                 onClick: (_, els) => { if (els.length) location.href = `${location.pathname}?scan=${d.churn[els[0].index].id}`; } },
    });
  }
  euLine(h.map((s) => s.started.slice(0, 10)), h.map((s) => s.eu_pct),
         (_, els) => { if (els.length) location.href = `${location.pathname}?scan=${h[els[0].index].id}`; });
  doughnut("countries", d.countries);
  hbar("netnames", d.netnames, "Addresses");
}

// --- tools ---------------------------------------------------------------------------------------------------------
function renderRdap(box, r) {
  if (!r.found) { box.innerHTML = '<p class="muted">Not found in RDAP (unregistered, or the registry has no RDAP).</p>'; return; }
  const ents = r.entities.filter((e) => e.name).map((e) => `${esc(e.name)} <span class="muted">(${esc(e.roles.join(", "))})</span>`);
  box.innerHTML = `<dl class="facts">
    <dt>Domain</dt><dd>${esc(r.name)}</dd>
    <dt>Registered</dt><dd>${esc(r.registered || "—")}</dd>
    <dt>Changed</dt><dd>${esc(r.changed || "—")}</dd>
    <dt>Expires</dt><dd>${esc(r.expires || "—")}</dd>
    <dt>Status</dt><dd>${r.status.map((s) => `<span class="pill">${esc(s)}</span>`).join(" ") || "—"}</dd>
    <dt>DNSSEC</dt><dd>${r.dnssec ? '<span class="pill ok">signed</span>' : '<span class="pill warn">unsigned</span>'}</dd>
    <dt>Name servers</dt><dd class="mono">${r.nameservers.map(esc).join("<br>") || "—"}</dd>
    <dt>Contacts</dt><dd>${ents.join("<br>") || '<span class="muted">redacted</span>'}</dd>
    <dt>Source</dt><dd class="muted mono">${esc(r.source)}</dd></dl>`;
}
function renderEmail(box, scoreEl, r) {
  const names = { mx: "MX (mail servers)", spf: "SPF", dmarc: "DMARC", dkim: "DKIM", mta_sts: "MTA-STS", dnssec: "DNSSEC" };
  scoreEl.textContent = `score ${r.score}/12`;
  box.innerHTML = '<div class="checks">' + Object.entries(names).map(([k, label]) => {
    const c = r[k];
    const detail = k === "mx" ? c.hosts.map(esc).join(", ") : esc(c.record);
    return `<div class="check"><header>${label}<span class="pill ${c.status}">${c.status}</span></header>
      ${detail ? `<code>${detail}</code>` : ""}${c.notes.length ? `<ul>${c.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}</div>`;
  }).join("") + "</div>";
}
function toolsPage() {
  const form = $("[data-tools-form]");
  const rdapBox = $("[data-rdap]"), emailBox = $("[data-email]"), scoreEl = $("[data-score]");
  const run = async (domain) => {
    history.replaceState(null, "", `/tools?domain=${encodeURIComponent(domain)}`);
    rdapBox.innerHTML = emailBox.innerHTML = '<p class="muted">Looking up…</p>';
    scoreEl.textContent = "";
    const get = async (url) => { const r = await fetch(url); const j = await r.json(); if (!r.ok) throw new Error(j.error || r.status); return j; };
    get(`/api/rdap/${encodeURIComponent(domain)}`).then((r) => renderRdap(rdapBox, r))
      .catch((e) => { rdapBox.innerHTML = `<p class="bad-text">${esc(e.message)}</p>`; });
    get(`/api/email/${encodeURIComponent(domain)}`).then((r) => renderEmail(emailBox, scoreEl, r))
      .catch((e) => { emailBox.innerHTML = `<p class="bad-text">${esc(e.message)}</p>`; });
  };
  form.addEventListener("submit", (ev) => { ev.preventDefault(); run(form.domain.value.trim()); });
  if (form.domain.value) run(form.domain.value.trim());
}

// --- admin ---------------------------------------------------------------------------------------------------------
function adminCharts() {
  const d = pageData();
  const el = $("#visits");
  if (!d.length) { el.parentElement.innerHTML = '<p class="muted">No visits yet</p>'; return; }
  const series = (label, key, color) => ({ label, data: d.map((r) => r[key] || 0), backgroundColor: color, borderRadius: 4 });
  new Chart(el, {
    type: "bar",
    data: { labels: d.map((r) => r.day), datasets: [series("Page views", "views", css("--accent")),
      series("Visitors", "visitors", css("--accent-2")), series("Downloads", "downloads", "#f59e0b"),
      series("Scans", "scans", "#8b5cf6")] },
    options: { scales: { x: { grid: { display: false } }, y: { beginAtZero: true } } },
  });
}
// Styled confirmation popup for destructive actions (forms with data-confirm): a modal <dialog>, not window.confirm.
function confirmModal(message) {
  return new Promise((resolve) => {
    const dlg = document.createElement("dialog");
    dlg.className = "confirm";
    dlg.innerHTML =
      `<form method="dialog"><p>${esc(message)}</p>` +
      `<menu><button value="cancel" class="btn">Cancel</button>` +
      `<button value="ok" class="btn danger" autofocus>Confirm</button></menu></form>`;
    document.body.appendChild(dlg);
    dlg.addEventListener("close", () => { resolve(dlg.returnValue === "ok"); dlg.remove(); });
    dlg.showModal();
  });
}
$$("form[data-confirm]").forEach((f) => f.addEventListener("submit", (ev) => {
  if (f.dataset.confirmed) return;   // already confirmed in the modal: let this submit through
  ev.preventDefault();
  confirmModal(f.dataset.confirm).then((ok) => {
    if (!ok) return;
    f.dataset.confirmed = "1";
    f.requestSubmit ? f.requestSubmit() : f.submit();
  });
}));

// route form (Settings · Routes): only the chosen kind's fields; without this script all of them show and work
$$("form[data-route-form]").forEach((f) => {
  const kind = $("select[data-kind-select]", f);
  const show = () => $$("[data-kind]", f).forEach((d) => { d.hidden = d.dataset.kind !== kind.value; });
  kind.addEventListener("change", show);
  show();
});

// a pick-list that applies itself (CSP allows no inline handlers); data-reset names a field to clear first
document.querySelectorAll("select[data-autosubmit], input[type=checkbox][data-autosubmit]").forEach((s) => s.addEventListener("change", () => {
  const other = s.dataset.reset && s.form.elements[s.dataset.reset];
  if (other) other.value = "";
  s.form.submit();
}));

// posture scan progress: the scan forms post in the background and a dialog follows that batch (posture_scans row
// ids) by polling the status endpoint every 2 s while open. Closing it leaves the scans running; the pill reopens it.
// Nothing reloads by itself: "Show results" reloads once. Without the dialog markup the forms post as usual.
function postureProgress() {
  const dlg = $("#posture-progress");
  if (!dlg) return;
  const KEY = "domin-posture-batch";
  const reopen = $("[data-pp-reopen]"), fill = $("[data-pp-fill]", dlg), bar = $(".bar", dlg);
  const st = { ids: [], last: null, at: 0, timer: 0, tick: 0, error: "" };
  const load = () => { try { return JSON.parse(sessionStorage.getItem(KEY)) || []; } catch (e) { return []; } };
  const keep = (ids) => { try { if (ids.length) sessionStorage.setItem(KEY, JSON.stringify(ids)); else sessionStorage.removeItem(KEY); } catch (e) { /* not kept */ } };
  const secs = (s) => (s >= 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s} s`);
  const result = (it) => {
    if (it.status === "failed") return `<small class="bad-text">${esc(it.error || "failed")}</small>`;
    if (it.status === "running" && it.chunks > 1) return `<small>part ${it.chunks_done} of ${it.chunks} done · ${it.open_ports} open so far</small>`;
    if (it.status !== "done") return "";
    return `<small>${it.open_ports} port(s) · ${it.cves} CVE(s)${it.high ? ` · ${it.high} high+` : ""}</small>`;
  };
  const pill = (it) => {
    if (it.status === "done") return `<span class="pill sev-${["critical", "high", "medium", "low"].includes(it.worst) ? it.worst : "unknown"}">${esc(it.worst)}</span>`;
    return `<span class="pill ${esc(it.status)}">${esc(it.status)}</span>`;
  };
  function clock() {   // between polls only the elapsed time moves
    const d = st.last;
    if (!d) return;
    const elapsed = d.elapsed + (d.finished ? 0 : Math.round((Date.now() - st.at) / 1000));
    $("[data-pp-elapsed]", dlg).textContent = d.total ? secs(elapsed) : "";
  }
  function paint() {
    const d = st.last;
    if (st.error) { $("[data-pp-line]", dlg).textContent = st.error; }
    if (!d) return;
    const end = d.done + d.failed, pct = d.total ? Math.round(100 * end / d.total) : 0;
    clock();
    if (!st.error) {
      $("[data-pp-line]", dlg).textContent = d.total
        ? `${end}/${d.total} finished · ${d.running} running · ${d.queued} queued${d.failed ? ` · ${d.failed} failed` : ""}`
        : "No posture scans to follow.";
    }
    fill.style.width = `${pct}%`;
    bar.setAttribute("aria-valuenow", pct);
    $("[data-pp-now]", dlg).textContent = d.current.length ? `Scanning: ${d.current.join(", ")}` : "";
    const shown = [...d.items.filter((i) => i.status === "running"),
                   ...d.items.filter((i) => i.status === "done" || i.status === "failed")
                     .sort((a, b) => (a.finished < b.finished ? 1 : -1))];
    $("[data-pp-items]", dlg).innerHTML = shown.map((it) => `<li>${pill(it)}<span class="what"><b>${esc(it.ip)}</b>` +
      `${it.host ? ` <span class="muted">${esc(it.host)}</span>` : ""}</span>${result(it)}</li>`).join("");
    $("[data-pp-done]", dlg).hidden = !(d.finished && d.total);
    $("[data-pp-show]", dlg).hidden = !(d.finished && d.total);
    const left = d.queued + d.running;
    if (reopen) { reopen.hidden = !left; $("[data-pp-count]", reopen).textContent = left; }
  }
  async function poll(extra = "") {
    clearTimeout(st.timer);
    try {
      const r = await fetch(`${dlg.dataset.status}?ids=${st.ids.join(",")}${extra}`, { headers: { Accept: "application/json" } });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      st.last = d; st.at = Date.now(); st.error = "";
      st.ids = d.ids;
      keep(d.finished ? [] : d.ids);
    } catch (e) {
      st.error = `Lost contact with the server (${e.message}), retrying…`;
    }
    paint();
    if (dlg.open && !(st.last?.finished && !st.error)) st.timer = setTimeout(poll, 2000);
  }
  function open(ids, extra = "", error = "") {
    st.ids = [...new Set([...load(), ...ids])];
    st.last = null; st.error = error;
    $("[data-pp-line]", dlg).textContent = error || "Loading…";
    $("[data-pp-now]", dlg).textContent = $("[data-pp-elapsed]", dlg).textContent = "";
    $("[data-pp-items]", dlg).innerHTML = "";
    fill.style.width = "0";
    $("[data-pp-done]", dlg).hidden = $("[data-pp-show]", dlg).hidden = true;
    if (!dlg.open) dlg.showModal();
    clearInterval(st.tick);
    if (error) return;   // the request was refused: show why, nothing to follow
    st.tick = setInterval(clock, 1000);
    poll(extra);
  }
  dlg.addEventListener("close", () => { clearTimeout(st.timer); clearInterval(st.tick); });
  $$("[data-pp-close]", dlg).forEach((b) => b.addEventListener("click", () => dlg.close()));
  $("[data-pp-show]", dlg).addEventListener("click", () => { keep([]); location.reload(); });
  reopen?.querySelector("a").addEventListener("click", (ev) => {
    ev.preventDefault();
    open([], `&pending=1&domain=${encodeURIComponent(dlg.dataset.domain || "")}`);
  });
  $$("form[data-posture-run]").forEach((f) => f.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = ev.submitter || $("button", f);
    if (btn) btn.disabled = true;
    try {
      const r = await fetch(f.action, { method: "POST", body: new URLSearchParams(new FormData(f)),
                                        headers: { Accept: "application/json" } });
      let d = {};
      try { d = await r.json(); } catch (e) { /* an HTML error page */ }
      if (!r.ok) throw new Error(d.error || (r.status === 403 ? "The form expired; reload the page and try again." : `HTTP ${r.status}`));
      open(d.batch || []);
    } catch (e) {
      open([], "", e.message);
    } finally {
      if (btn) btn.disabled = false;
    }
  }));
}
postureProgress();

// posture report charts (data: #posture-data, posture.report + trend). Severity colours come from the --sev-* vars,
// read at render time like every chart colour; an empty series shows a sentence instead of an empty canvas.
function postureCharts() {
  const el = document.getElementById("posture-data");
  if (!el) return;
  const d = JSON.parse(el.textContent);
  const SEV = ["critical", "high", "medium", "low", "unknown"];
  const sevColour = (s) => css(`--sev-${s}`);
  const gap = { borderColor: css("--surface"), borderWidth: 1, borderRadius: 3, maxBarThickness: 22 };
  const canvas = (id, rows, empty) => {
    const c = document.getElementById(id);
    if (c && !rows?.length) { c.parentElement.innerHTML = `<p class="muted chart-empty">${esc(empty)}</p>`; return null; }
    return c;
  };
  const ints = { beginAtZero: true, ticks: { precision: 0 } };
  const short = (s) => (s.length > 26 ? `${s.slice(0, 25)}…` : s);

  // where to act first: the addresses with the most severe CVEs, stacked by severity; a click opens the address
  const hosts = d.hosts || [];
  let c = canvas("pc-hosts", hosts, "No CVEs on any scanned address.");
  if (c) {
    const used = SEV.filter((s) => hosts.some((h) => h[s]));
    new Chart(c, {
      type: "bar",
      data: { labels: hosts.map((h) => h.label),
              datasets: used.map((s) => ({ label: s, data: hosts.map((h) => h[s]), backgroundColor: sevColour(s), ...gap })) },
      options: { indexAxis: "y", plugins: { legend: { position: "top" },
                 tooltip: { callbacks: { title: (it) => `${hosts[it[0].dataIndex].label} (${hosts[it[0].dataIndex].ip})` } } },
                 scales: { x: { stacked: true, ...ints }, y: { stacked: true, grid: { display: false }, ticks: { callback: (v) => short(hosts[v].label) } } },
                 onHover: (ev, els) => { ev.native.target.style.cursor = els.length ? "pointer" : ""; },
                 onClick: (_, els) => {
                   const box = els.length && document.getElementById(hosts[els[0].index].anchor);
                   if (!box) return;
                   box.open = true;
                   box.scrollIntoView({ behavior: "smooth", block: "start" });
                 } },
    });
  }

  // what an update removes today (accent) versus what waits on a vendor (grey): emphasis on the actionable part
  const fix = d.fix || [];
  c = canvas("pc-fix", fix, "No CVEs.");
  if (c) {
    new Chart(c, {
      type: "bar",
      data: { labels: fix.map((r) => r.label),
              datasets: [{ label: "Fix published", data: fix.map((r) => r.fix), backgroundColor: css("--accent"), ...gap },
                         { label: "No fix yet", data: fix.map((r) => r.nofix), backgroundColor: css("--sev-unknown"), ...gap }] },
      options: { indexAxis: "y", plugins: { legend: { position: "top" } },
                 scales: { x: { stacked: true, ...ints }, y: { stacked: true, grid: { display: false } } } },
    });
  }

  // better or worse: distinct critical and high CVEs per day with a finished scan
  const tr = d.trend || [];
  c = canvas("pc-trend", tr, "The trend appears once scans have finished on two or more days.");
  if (c) {
    const line = (s) => ({ label: s, data: tr.map((r) => r[s]), borderColor: sevColour(s), backgroundColor: sevColour(s),
                           borderWidth: 2, tension: .2, pointRadius: tr.length > 40 ? 0 : 4, pointHoverRadius: 6 });
    new Chart(c, {
      type: "line",
      data: { labels: tr.map((r) => r.day), datasets: [line("critical"), line("high")] },
      options: { interaction: { mode: "index", intersect: false }, plugins: { legend: { position: "top" } },
                 scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: ints } },
    });
  }

  // how current the picture is: fresh results good, stale a warning, failed a fault
  const age = (d.age || []).some((r) => r.n) ? d.age : [];
  c = canvas("pc-age", age, "No results yet.");
  if (c) {
    const tone = { "under 7 days": css("--up"), failed: css("--down") };
    new Chart(c, {
      type: "bar",
      data: { labels: age.map((r) => r.label), datasets: [{ label: "Addresses", data: age.map((r) => r.n), ...gap,
              backgroundColor: age.map((r) => tone[r.label] || (r.label.startsWith("over") ? css("--flat") : css("--sev-unknown"))) }] },
      options: { indexAxis: "y", plugins: { legend: { display: false } },
                 scales: { x: ints, y: { grid: { display: false } } } },
    });
  }

  // what is listening: ranked bars, one hue
  const svc = d.services || [];
  c = canvas("pc-services", svc, "No open ports found.");
  if (c) {
    new Chart(c, {
      type: "bar",
      data: { labels: svc.map((r) => r.label), datasets: [{ label: "Open ports", data: svc.map((r) => r.n), backgroundColor: css("--accent"), ...gap }] },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: ints, y: { grid: { display: false } } } },
    });
  }
}

const page = document.body.dataset.page;
if (page === "tools") toolsPage();
if (chartDefaults()) {
  postureCharts();
  if (page === "overview") overviewCharts();
  if (page === "domain") domainCharts();
  if (page === "all") allCharts();
  if (page === "admin") adminCharts();
}
