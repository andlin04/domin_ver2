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

const page = document.body.dataset.page;
if (page === "tools") toolsPage();
if (chartDefaults()) {
  if (page === "overview") overviewCharts();
  if (page === "domain") domainCharts();
  if (page === "all") allCharts();
  if (page === "admin") adminCharts();
}
