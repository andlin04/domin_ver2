"use strict";
// Drilldown (All) in the browser: the whole dataset is fetched once (gzip'd JSON the browser caches until the next
// scan), then the search, column filters, sorting, figures, charts and pages are computed here as you type, without
// asking the server. Without the data (no JavaScript, a network error) the page works the server way: Enter searches.
// Needs app.js ($, $$, ipKey).
(() => {
  const box = $("[data-drill]");
  const form = $("#search-form");
  if (!box || !form || !window.fetch) return;
  const SEARCH = ["host", "ip", "asn", "prefix", "netname", "descr", "country"];
  const PAGE = 100;
  const full = box.hasAttribute("data-full");   // the Drilldown page (figures, charts, pages); else the overview tab
  const fmt = (n) => n.toLocaleString("en-US");
  const say = (t) => { const s = $("[data-drill-status]", box); if (s) s.textContent = t; };
  let data = null, view = [], pageNo = 1, sortKey = "", sortType = "text", sortDir = 1, timer = 0, loading = null;

  const decode = (j) => {
    const cols = {};
    for (const [k, c] of Object.entries(j.columns)) cols[k] = Array.isArray(c) ? { v: c } : { d: c.d, i: c.i };
    return { n: j.rows, cols, eu: new Set(j.eu), history: "seen" in cols };
  };
  const val = (k, r) => { const c = data.cols[k]; return c.d ? c.d[c.i[r]] : c.v[r]; };
  const lower = (v) => String(v ?? "").toLowerCase();
  // a test per column; a column of repeated values tests each distinct value once. "!text" = rows without it;
  // EU matches from the start, so "eu" isn't "Non-EU" (the server fallback does the same)
  const test = (k, text, plain = false) => {
    const neg = !plain && text.startsWith("!");
    const t = neg ? text.slice(1) : text;
    if (!t) return () => true;
    const has = k === "eu" ? (v) => v.startsWith(t) !== neg : (v) => v.includes(t) !== neg;
    const c = data.cols[k];
    if (!c) { console.warn("drilldown: no column", k); return () => true; }
    if (c.d) { const ok = c.d.map((v) => has(lower(v))); return (r) => ok[c.i[r]]; }
    const low = c.low || (c.low = c.v.map(lower));
    return (r) => has(low[r]);
  };

  const colBoxes = () => $$('.colf[form="search-form"]');
  const state = () => ({
    q: form.q.value.trim(), field: form.field.value, scope: form.scope.value,
    cols: Object.fromEntries(colBoxes().map((i) => [i.name.slice(2), i.value.trim()]).filter(([, v]) => v)),
  });
  const params = (st) => {
    const p = new URLSearchParams({ q: st.q });
    if (st.field) p.set("field", st.field);
    p.set("scope", st.scope);
    for (const [k, v] of Object.entries(st.cols)) p.set("f_" + k, v);
    return p;
  };

  function filter(st) {
    const tests = Object.entries(st.cols).map(([k, v]) => test(k, v.toLowerCase()));
    if (st.q) {
      const any = (st.field ? [st.field] : SEARCH).map((k) => test(k, st.q.toLowerCase(), true));   // search: plain text
      tests.push((r) => any.some((t) => t(r)));
    }
    const out = [];
    for (let r = 0; r < data.n; r++) if (tests.every((t) => t(r))) out.push(r);
    return out;
  }

  function sortView() {
    if (!sortKey) return;
    const key = (r) => {
      const v = val(sortKey, r) ?? "";
      return sortType === "num" ? (parseFloat(v) || 0) : sortType === "ip" ? ipKey(String(v)) : lower(v);
    };
    const ks = view.map(key);
    const order = view.map((_, i) => i).sort((a, b) => (ks[a] > ks[b] ? 1 : ks[a] < ks[b] ? -1 : 0) * sortDir);
    view = order.map((i) => view[i]);
  }

  // the same figures as the server's search_summary: distinct values, EU share of located addresses, top 10 bars
  function figures() {
    const sets = { hosts: new Set(), ips: new Set(), domains: new Set(), asns: new Set(), countries: new Set() };
    const from = { hosts: "host", ips: "ip", domains: "domain", asns: "asn", countries: "country" };
    const by = { country: new Map(), netname: new Map(), asn: new Map() };
    const located = new Set();
    let eu = 0;
    for (const r of view) {
      for (const k in sets) { const v = val(from[k], r); if (v !== "") sets[k].add(v); }
      const ip = val("ip", r);
      if (!ip) continue;
      for (const k in by) {
        const v = val(k, r);
        if (v === "") continue;
        let s = by[k].get(v);
        if (!s) by[k].set(v, (s = new Set()));
        s.add(ip);
      }
      const country = val("country", r);
      if (country && !located.has(ip + "|" + country)) { located.add(ip + "|" + country); if (data.eu.has(country)) eu++; }
    }
    const top = (m) => [...m].map(([label, s]) => ({ label, ips: s.size })).sort((a, b) => b.ips - a.ips).slice(0, 10);
    const out = Object.fromEntries(Object.entries(sets).map(([k, s]) => [k, s.size]));
    out.eu_pct = located.size ? Math.round((1000 * eu) / located.size) / 10 : null;
    out.countries_top = top(by.country); out.netnames_top = top(by.netname); out.asns_top = top(by.asn);
    return out;
  }

  const td = (cls, text) => {
    const c = document.createElement("td");
    if (cls) c.className = cls;
    c.textContent = text ?? "";
    return c;
  };
  function renderRows() {
    const frag = document.createDocumentFragment();
    for (const r of view.slice((pageNo - 1) * PAGE, pageNo * PAGE)) {
      const tr = document.createElement("tr");
      const a = document.createElement("a");
      a.href = "/d/" + val("domain", r);
      a.textContent = val("domain", r);
      const dom = td("", ""); dom.append(a);
      const div = document.createElement("div");
      div.className = "lines2";
      div.title = div.textContent = val("descr", r);
      const descr = td("text", ""); descr.append(div);
      tr.append(td("host", val("host", r)), dom, td("mono", val("ip", r) || "—"), td("num", val("asn", r)),
        td("mono", val("prefix", r)), td("text net", val("netname", r)), descr,
        td(val("eu", r) === "EU" ? "eu" : val("eu", r) ? "non-eu" : "", val("eu", r)), td("", val("country", r)));
      if (data.history) tr.append(td("", val("first_seen", r)));
      tr.append(td("", val("last_seen", r)));
      if (data.history) tr.append(td("num", val("seen", r)));
      frag.append(tr);
    }
    if (!view.length) { const tr = document.createElement("tr"); const c = td("muted", "No matches."); c.colSpan = 12; tr.append(c); frag.append(tr); }
    $("#results", box).tBodies[0].replaceChildren(frag);
  }

  function renderPager() {
    const nav = $("#pager", box);
    if (!nav) return;
    const pages = Math.max(1, Math.ceil(view.length / PAGE));
    const btn = (text, to) => {
      const b = document.createElement("button");
      b.type = "button"; b.className = "btn small"; b.textContent = text;
      b.addEventListener("click", () => { pageNo = to; renderRows(); renderPager(); syncUrl(); box.scrollIntoView(); });
      return b;
    };
    const parts = [];
    if (pages > 1) {
      if (pageNo > 1) parts.push(btn("← Previous", pageNo - 1));
      const s = document.createElement("span"); s.className = "muted"; s.textContent = `Page ${fmt(pageNo)} of ${fmt(pages)}`;
      parts.push(s);
      if (pageNo < pages) parts.push(btn("Next →", pageNo + 1));
    }
    nav.replaceChildren(...parts);
  }

  function renderFigures() {
    const f = figures();
    for (const el of $$("[data-k]")) {
      const v = f[el.dataset.k];
      el.textContent = el.dataset.k === "eu_pct" ? (v === null ? "—" : `${v.toFixed(1)} %`) : fmt(v);
    }
    for (const id of ["countries", "netnames", "asns"]) {
      const chart = window.Chart && Chart.getChart(document.getElementById(id));
      if (!chart) continue;
      chart.data.labels = f[id + "_top"].map((r) => r.label);
      chart.data.datasets[0].data = f[id + "_top"].map((r) => r.ips);
      chart.update("none");
    }
  }

  function syncUrl() {
    const st = state();
    const p = params(st);
    const csv = $("#csv");
    if (csv) { csv.href = "/search.csv?" + p; csv.hidden = !view.length; }
    const clear = $("#clear-cols");
    if (clear) clear.hidden = !Object.keys(st.cols).length;
    const open = $("#drill-open");
    if (open) open.href = "/all?" + p;
    if (full) {
      if (pageNo > 1) p.set("page", pageNo);
      history.replaceState(null, "", "/all?" + p);
    }
  }

  function apply(firstPage = true) {
    if (!data) return;
    const t0 = performance.now();
    view = filter(state());
    sortView();
    const pages = Math.max(1, Math.ceil(view.length / PAGE));
    pageNo = firstPage ? 1 : Math.min(pageNo, pages);
    renderRows();
    renderPager();
    if (full) renderFigures();
    syncUrl();
    const what = data.history ? "host and address pairs" : "records";
    const total = $("[data-total]");
    if (total) total.textContent = `${fmt(view.length)} ${what}`;
    say(`${fmt(view.length)} ${what} match. Filtered in your browser in ${Math.round(performance.now() - t0)} ms.`);
  }

  function load() {
    if (loading) return loading;
    say("Loading the records into your browser…");
    loading = fetch(box.dataset.drill)
      .then((r) => { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then((j) => {
        data = decode(j);
        pageNo = parseInt(new URLSearchParams(location.search).get("page"), 10) || 1;
        apply(false);
      })
      .catch((err) => {
        console.error("drilldown data:", err);
        data = null;   // back to the server way
        say("Press Enter to apply (the records could not be loaded into your browser).");
      });
    return loading;
  }

  // typing filters at once; Enter on the overview opens the full Drilldown; another scope loads that page
  document.addEventListener("input", (ev) => {
    if (!data || ev.target.form !== form || ev.target.name === "scope") return;
    clearTimeout(timer);
    timer = setTimeout(apply, data.history ? 250 : 120);
  });
  form.scope.addEventListener("change", () => { if (data) form.requestSubmit(); });
  form.addEventListener("submit", (ev) => {
    if (!data || !full || form.scope.value !== box.dataset.scope) return;
    ev.preventDefault();
    clearTimeout(timer);
    apply();
  });
  $("#clear-cols")?.addEventListener("click", (ev) => {
    if (!data) return;
    ev.preventDefault();
    colBoxes().forEach((i) => { i.value = ""; });
    apply();
  });
  // sorting covers every match, not only the rows shown
  $("#results thead", box)?.addEventListener("click", (ev) => {
    const th = ev.target.closest("th[data-sort]");
    if (!data || !th) return;
    ev.stopPropagation();
    const keys = ["host", "domain", "ip", "asn", "prefix", "netname", "descr", "eu", "country",
      ...(data.history ? ["first_seen", "last_seen", "seen"] : ["last_seen"])];
    const k = keys[[...th.parentElement.children].indexOf(th)];
    sortDir = sortKey === k ? -sortDir : 1;
    sortKey = k;
    sortType = th.dataset.sort;
    $$("th", th.parentElement).forEach((h) => delete h.dataset.dir);
    th.dataset.dir = sortDir === 1 ? "asc" : "desc";
    view = filter(state());
    sortView();
    pageNo = 1;
    renderRows();
    renderPager();
  }, true);

  if (full || location.hash === "#drill") load();
  $('[data-tab="drill"]')?.addEventListener("click", load);
})();
