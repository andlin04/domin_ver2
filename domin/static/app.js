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
// every table sorts on its column headers: a header without data-sort gets a type from its column's cells
// (#results: the drill sorts all its matches itself)
$$(".table-wrap table, table.sortable").forEach((table) => {
  if (table.id === "results" || !table.tHead || !table.tBodies[0]) return;
  table.classList.add("sortable");
  const rows = [...table.tBodies[0].rows].filter((r) => !r.classList.contains("detail-row"));
  $$("thead th", table).forEach((th) => {
    if (th.dataset.sort || th.classList.contains("tick") || th.colSpan > 1 || !th.textContent.trim()) return;
    const vals = rows.map((r) => r.cells[th.cellIndex]).filter(Boolean)
      .map((c) => (c.dataset.key ?? c.textContent).trim()).filter((v) => v && v !== "—" && v !== "-");
    const all = (re) => vals.length > 0 && vals.every((v) => re.test(v));
    th.dataset.sort = all(/^\d{1,3}(\.\d{1,3}){3}$/) ? "ip" : all(/^-?\d+(\.\d+)?\s*%?$/) ? "num" : "text";
  });
});
$$("table.sortable").forEach((table) => {
  $$("th[data-sort]", table).forEach((th) => th.addEventListener("click", () => {
    const type = th.dataset.sort;
    const col = th.cellIndex;   // not the index among sortable headers: a tick column has none
    const dir = th.dataset.dir === "asc" ? "desc" : "asc";
    $$("th", table).forEach((h) => delete h.dataset.dir);
    th.dataset.dir = dir;
    const body = table.tBodies[0];
    const key = (tr) => {
      const c = tr.cells[col];
      if (!c) return "";   // an empty-list row spans the table
      const t = (c.dataset.key ?? c.textContent).trim();   // data-key: a sort value other than the text
      if (type === "num") return parseFloat(t) || 0;
      return type === "ip" ? ipKey(t) : t.toLowerCase();
    };
    const rows = [...body.rows].filter((r) => !r.classList.contains("detail-row"))
      .sort((a, b) => (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0) * (dir === "asc" ? 1 : -1));
    body.append(...rows);
    rows.forEach((r) => { if (r._detail) r.after(r._detail); });   // an expanded row keeps its details under it
  }));
});
document.addEventListener("click", (ev) => { if (ev.target.closest("th .colf")) ev.stopPropagation(); }, true);
// the Filter box (all words, anywhere in the row) and a box per column (text in that column) add up
function applyFilters(table) {
  const words = ($(`[data-filter="#${table.id}"]`)?.value || "").toLowerCase().split(/\s+/).filter(Boolean);
  const cols = $$("thead th", table).map((th) => ($(".colf", th)?.value || "").trim().toLowerCase());
  if (words.length) { const box = table.closest("details"); if (box) box.open = true; }   // a collapsed table shows its matches
  const start = $$("thead th", table).map((th) => th.dataset.match === "start");   // EU: "eu" isn't "Non-EU"
  const cell = (tr, i) => (tr.cells[i]?.textContent || "").trim().toLowerCase();
  const has = (v, t, i) => (start[i] ? v.startsWith(t) : v.includes(t));
  const ok = (c, v, i) => c[0] === "!" ? !c.slice(1) || !has(v, c.slice(1), i) : has(v, c, i);   // "!text": without it
  for (const tr of table.tBodies[0].rows) {
    if (tr.classList.contains("detail-row")) continue;   // follows its host row
    const text = tr.textContent.toLowerCase();
    tr.hidden = !words.every((w) => text.includes(w)) || !cols.every((c, i) => !c || ok(c, cell(tr, i), i));
    if (tr._detail) tr._detail.hidden = tr.hidden;
  }
}
$$("table[data-colfilters]").forEach((table) => {
  $$("thead th", table).forEach((th) => {
    if (th.hasAttribute("data-nofilter")) return;
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
// resizable columns (table[data-resizable] with a <colgroup>): drag a header's right edge; widths kept per browser
$$("table[data-resizable]").forEach((table) => {
  const cols = $$("colgroup col", table);
  const store = `colw:${table.id}`;
  let saved = [];
  try { saved = JSON.parse(localStorage.getItem(store) || "[]"); } catch (e) { saved = []; }
  if (saved.length === cols.length) cols.forEach((c, i) => { c.style.width = saved[i]; });
  const fit = () => { table.style.width = `${cols.reduce((s, c) => s + c.getBoundingClientRect().width, 0)}px`; };
  $$("thead th", table).forEach((th, i) => {
    if (!cols[i]) return;
    const grip = document.createElement("span");
    grip.className = "col-resize";
    grip.setAttribute("aria-hidden", "true");
    grip.addEventListener("click", (ev) => ev.stopPropagation());   // not a sort click
    grip.addEventListener("pointerdown", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      const x0 = ev.clientX;
      const w0 = cols[i].getBoundingClientRect().width;
      grip.classList.add("dragging");
      grip.setPointerCapture(ev.pointerId);
      const move = (e) => { cols[i].style.width = `${Math.max(40, w0 + e.clientX - x0)}px`; fit(); };
      const up = () => {
        grip.classList.remove("dragging");
        grip.removeEventListener("pointermove", move);
        localStorage.setItem(store, JSON.stringify(cols.map((c) => c.style.width)));
      };
      grip.addEventListener("pointermove", move);
      grip.addEventListener("pointerup", up, { once: true });
    });
    th.append(grip);
  });
  fit();
});
// posture host table: a host name expands a row under it with its addresses' findings (the <details> trees, moved
// from the hidden #pa-pool and put back on collapse). An address shared by two names shows under one at a time.
function collapseHost(tr) {
  const pool = document.getElementById("pa-pool");
  if (!tr?._detail) return;
  pool.append(...$$("details.posture-detail", tr._detail));
  tr._detail.remove();
  tr._detail = null;
  tr.classList.remove("expanded");
}
function expandHost(a, openId) {
  const tr = a.closest("tr");
  const panel = tr.closest("[data-panel]");   // e.g. a link on the CVEs tab: show the Hosts tab first
  if (panel?.hidden) panel.closest("[data-tabs]")._show(panel.dataset.panel);
  if (!tr._detail) {
    const ids = a.dataset.hostDetails.split(" ");
    const boxes = ids.map((id) => document.getElementById(id)).filter(Boolean);
    boxes.forEach((b) => { const other = b.closest("tr.detail-row"); if (other) collapseHost(other._host); });
    const row = document.createElement("tr");
    row.className = "detail-row";
    row._host = tr;
    const td = document.createElement("td");
    td.colSpan = tr.cells.length;
    td.append(...boxes);
    boxes.forEach((b) => { b.open = boxes.length === 1; });
    row.append(td);
    row.hidden = tr.hidden;
    tr.after(row);
    tr._detail = row;
    tr.classList.add("expanded");
  }
  const box = openId && document.getElementById(openId);
  if (box) box.open = true;
  (box || tr).scrollIntoView({ behavior: "smooth", block: "nearest" });
}
// from a chart or a CVE-table link: expand the host row that holds this address
function hostDetails(id) {
  const a = $$("a[data-host-details]").find((x) => x.dataset.hostDetails.split(" ").includes(id));
  if (a) expandHost(a, id);
}
document.addEventListener("click", (ev) => {
  const a = ev.target.closest("a[data-host-details]");
  if (!a) return;
  ev.preventDefault();
  const tr = a.closest("tr");
  if (tr._detail) collapseHost(tr); else expandHost(a);
});
// tick tables (posture hosts, posture domains): the header box ticks every visible row; the card's buttons
// ("Scan now": profile, "Report": format) open their dialog for the ticked rows that are still visible
$$("table[data-picker]").forEach((table) => {
  const card = table.closest("section") || document;
  const btns = $$("[data-picked-open]", card);
  if (!btns.length) return;
  const all = $("[data-pick-all]", table);
  const count = $("[data-picked-count]", card);
  const shown = (b) => { const tr = b.closest("tr"); return !tr.hidden && !tr.classList.contains("pf-out"); };
  const picked = () => $$("tbody input[data-pick]", table).filter((b) => b.checked && shown(b));
  const sync = () => {
    const n = picked().length;
    btns.forEach((b) => { b.disabled = !n; });
    count.textContent = `${n} ticked`;
  };
  all.addEventListener("change", () => {
    $$("tbody input[data-pick]", table).forEach((b) => { if (shown(b)) b.checked = all.checked; });
    sync();
  });
  table.addEventListener("change", sync);
  document.addEventListener("pagefilter", sync);
  document.addEventListener("input", (ev) => { if (ev.target.matches(`.colf, [data-filter='#${table.id}']`)) sync(); });
  btns.forEach((btn) => {
    const dlg = $(btn.dataset.pickedOpen);
    btn.addEventListener("click", () => {
      const names = picked().map((b) => b.value);
      $("input[data-picked-names]", dlg).value = names.join(",");
      $("[data-picked-n]", dlg).textContent = names.length;
      dlg.showModal();
    });
    $("[data-cancel]", dlg).addEventListener("click", () => dlg.close());
    // Scan: the posture-run handler sends it and shows progress; Report: the browser downloads the file
    $("form", dlg).addEventListener("submit", () => dlg.close());
  });
});
// posture: Scan opens the confirm dialog (target + profile); Confirm submits the form the dialog sits in
$$("[data-scan-open]").forEach((btn) => {
  const dlg = $(btn.dataset.scanOpen);
  const ask = () => {
    $("[data-scan-what]", dlg).textContent = $("[data-scan-target]", btn.form)?.value || "the whole domain";
    dlg.showModal();
  };
  btn.addEventListener("click", ask);
  $("[data-cancel]", dlg).addEventListener("click", () => dlg.close());
  // registered before the posture-run handler: Enter in a field asks first instead of scanning
  btn.form.addEventListener("submit", (ev) => {
    if (dlg.open) { dlg.close(); return; }
    ev.preventDefault();
    ev.stopImmediatePropagation();
    ask();
  });
});
// a link to a collapsed section (posture: CVE findings -> the address) opens it before scrolling there
document.addEventListener("click", (ev) => {
  const a = ev.target.closest("a[data-open-details]");
  const box = a && document.getElementById(a.getAttribute("href").slice(1));
  if (!box) return;
  ev.preventDefault();
  if (box.closest("#pa-pool, #posture-hosts")) { hostDetails(box.id); return; }   // lives in the host table
  box.open = true;
  box.scrollIntoView({ behavior: "smooth", block: "start" });
  history.replaceState(null, "", a.getAttribute("href"));
});
// search page: empty boxes stay out of the address
$("#search-form")?.addEventListener("formdata", (ev) => {
  for (const [k, v] of [...ev.formData]) if (!v && k !== "q") ev.formData.delete(k);
});
// tabbed cards: one panel shown; a tab other than the first is kept in the address (#drill, #cves)
$$("[data-tabs]").forEach((card) => {
  const tabs = $$("[data-tab]", card);
  const show = (name) => {
    tabs.forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    $$("[data-panel]", card).forEach((p) => { p.hidden = p.dataset.panel !== name; });
  };
  card._show = show;
  tabs.forEach((b) => b.addEventListener("click", () => {
    show(b.dataset.tab);
    history.replaceState(null, "", b === tabs[0] ? location.pathname + location.search : `#${b.dataset.tab}`);
  }));
  const named = tabs.find((b) => `#${b.dataset.tab}` === location.hash);
  if (named) show(named.dataset.tab);
});
// Posture domain search: the server says which domains hold every typed word (any case, any attribute); the Domain
// list keeps only those. Options are taken out, not hidden (iOS ignores hidden options). Enter opens the first match.
// The same box filters the page's lists: domain rows by the server's answer, host and CVE rows by their data-text
// (class pf-out, so the column filters' own hiding stays separate); an expanded host's detail row follows its row.
$$("[data-domain-search]").forEach((box) => {
  const sel = $(".posture-pick select[name=domain]");
  const count = $("[data-domain-count]", box.closest(".field"));
  const all = [...sel.options].filter((o) => o.value);
  let hits = all;
  let timer;
  let seq = 0;
  const rows = (id) => $$(`#${id} > tbody > tr:not(.detail-row)`);
  const out = (tr, gone) => { tr.classList.toggle("pf-out", gone); tr._detail?.classList.toggle("pf-out", gone); };
  const show = (names) => {
    hits = names ? all.filter((o) => names.has(o.value)) : all;
    // the shown domain stays listed so the picker keeps showing it; the rest in name order
    all.forEach((o) => { if (hits.includes(o) || o.selected) sel.append(o); else o.remove(); });
    const words = box.value.toLowerCase().split(/\s+/).filter(Boolean);
    const parts = [names ? `${hits.length} of ${all.length} domains` : `${all.length} domains`];
    rows("posture-domains").forEach((tr) => out(tr, !!names && !names.has(tr.dataset.domain)));
    for (const [id, what] of [["posture-hosts", "hosts"], ["posture-cves", "CVEs"]]) {
      const list = rows(id);
      if (!list.length) continue;
      list.forEach((tr) => out(tr, !words.every((w) => tr.dataset.text.includes(w))));
      if (words.length) parts.push(`${list.filter((tr) => !tr.classList.contains("pf-out")).length} of ${list.length} ${what}`);
    }
    count.textContent = parts.join(" · ");
    box.dispatchEvent(new Event("pagefilter", { bubbles: true }));   // the host picker recounts its ticks
  };
  const search = async () => {
    const q = box.value.trim();
    if (!q) { show(null); return; }
    const mine = ++seq;
    count.textContent = "searching…";
    try {
      const r = await fetch(`${box.dataset.domainSearch}?q=${encodeURIComponent(q)}`, { headers: { Accept: "application/json" } });
      const d = await r.json();
      if (mine === seq) show(new Set(d.domains || []));
    } catch {
      if (mine === seq) count.textContent = "search failed";
    }
  };
  box.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 250); });
  box.addEventListener("keydown", async (ev) => {
    if (ev.key !== "Enter") return;
    ev.preventDefault();
    clearTimeout(timer);
    await search();
    if (!box.value.trim() || !hits.length || hits[0].selected) return;
    sel.value = hits[0].value;
    sel.dispatchEvent(new Event("change", { bubbles: true }));
  });
});
// nav Admin menu: a click elsewhere or Escape closes it
document.addEventListener("click", (ev) => {
  $$("[data-nav-menu][open]").forEach((m) => { if (!m.contains(ev.target)) m.open = false; });
});
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") $$("[data-nav-menu][open]").forEach((m) => { m.open = false; });
});
// posture ?host=: that host's row opens on load
$$("a[data-auto-open]").forEach((a) => expandHost(a));
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
    // a new scan follows only its own batch (earlier unfinished batches may be other domains); the "N left" link
    // follows the pending rows; only a bare reopen falls back to the batch kept in this tab
    st.ids = ids.length || extra ? ids : load();
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
      // nothing new queued (already pending): follow that domain's pending scans, not other domains'
      if (d.batch?.length) open(d.batch);
      else open([], `&pending=1&domain=${encodeURIComponent(d.domain || "")}`);
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

  // what an update removes today (accent) versus what waits on a vendor (grey): emphasis on the actionable part
  const fix = d.fix || [];
  let c = canvas("pc-fix", fix, "No CVEs.");
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

  // better or worse: distinct CVEs per severity per day with a finished scan (critical first, so it draws on top),
  // then the attack surface: open ports and addresses scanned
  const tr = d.trend || [];
  const lines = (id, series) => {
    const el = canvas(id, tr, "The trend appears once scans have finished on two or more days.");
    if (!el) return;
    const line = ([key, label, colour]) => ({ label, data: tr.map((r) => r[key]), borderColor: colour, backgroundColor: colour,
                                             borderWidth: 2, tension: .2, pointRadius: tr.length > 40 ? 0 : 3, pointHoverRadius: 6 });
    new Chart(el, {
      type: "line",
      data: { labels: tr.map((r) => r.day), datasets: series.map(line) },
      options: { interaction: { mode: "index", intersect: false }, plugins: { legend: { position: "top" } },
                 scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: ints } },
    });
  };
  lines("pc-trend", SEV.slice(0, 4).map((s) => [s, s, sevColour(s)]));
  lines("pc-surface", [["ports", "Open ports", css("--accent")], ["addresses", "Addresses scanned", css("--sev-unknown")]]);

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
