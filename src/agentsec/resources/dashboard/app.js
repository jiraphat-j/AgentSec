"use strict";

const view = document.getElementById("view");
const title = document.getElementById("view-title");
const status = document.getElementById("status");
const back = document.getElementById("back");
let backAction = null;

function element(name, text, className) {
  const node = document.createElement(name);
  if (text !== undefined) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function clearView(name, returnAction = null) {
  while (view.lastChild && view.lastChild !== title) view.removeChild(view.lastChild);
  title.textContent = name;
  backAction = returnAction;
  back.disabled = returnAction === null;
}

function valueText(value) {
  if (value === null || value === undefined) return "Unavailable";
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

async function request(path) {
  const response = await fetch(path, {headers: {"Accept": "application/json"}});
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json();
}

function dataTable(data, captionText = "Recorded fields") {
  const table = element("table");
  table.appendChild(element("caption", captionText));
  const body = element("tbody");
  Object.entries(data).forEach(([key, value]) => {
    const row = element("tr");
    row.appendChild(element("th", key.replaceAll("_", " ")));
    const cell = element("td");
    if (typeof value === "object" && value !== null) cell.appendChild(element("pre", valueText(value)));
    else cell.textContent = valueText(value);
    row.appendChild(cell); body.appendChild(row);
  });
  table.appendChild(body);
  return table;
}

function pager(host, page, load) {
  const controls = element("div", undefined, "pager");
  const first = page.total === 0 ? 0 : page.offset + 1;
  const last = Math.min(page.offset + page.items.length, page.total);
  controls.appendChild(element("span", `${first}–${last} of ${page.total}`));
  const previous = element("button", "Previous"); previous.type = "button";
  previous.disabled = page.offset === 0;
  previous.addEventListener("click", () => load(Math.max(0, page.offset - page.limit)).catch(showError));
  const next = element("button", "Next"); next.type = "button";
  next.disabled = page.offset + page.items.length >= page.total;
  next.addEventListener("click", () => load(page.offset + page.limit).catch(showError));
  controls.append(previous, next); host.appendChild(controls);
}

function evidenceButton(sourceId, reference, returnAction) {
  const button = element("button", `Event ${reference.sequence}: ${reference.event_id}`);
  button.type = "button"; button.disabled = !sourceId;
  button.addEventListener("click", () => showEvent(sourceId, reference.event_id, returnAction).catch(showError));
  return button;
}

async function showEvent(sourceId, eventId, returnAction) {
  status.textContent = "Loading exact evidence…";
  const event = await request(`/api/v1/runs/${encodeURIComponent(sourceId)}/events/${encodeURIComponent(eventId)}`);
  clearView(`Evidence ${event.event_id}`, returnAction);
  view.appendChild(dataTable(event));
  status.textContent = "Exact evidence loaded.";
  document.getElementById("content").focus();
}

async function renderRunTimeline(item, offset = 0, filters = {trace: "", type: ""}, returnAction = () => showDetail("runs", item)) {
  const old = document.getElementById("run-timeline");
  if (old) old.remove();
  const section = element("section"); section.id = "run-timeline";
  section.appendChild(element("h3", "Sequence-ordered timeline"));
  const form = element("form", undefined, "filters");
  const trace = element("input"); trace.placeholder = "Exact trace ID"; trace.value = filters.trace;
  const type = element("input"); type.placeholder = "Exact event type"; type.value = filters.type;
  const apply = element("button", "Apply filters"); apply.type = "submit";
  form.append(trace, type, apply); section.appendChild(form);
  const query = new URLSearchParams({offset: String(offset), limit: "50"});
  if (filters.trace) query.set("trace_id", filters.trace);
  if (filters.type) query.set("event_type", filters.type);
  const page = await request(`/api/v1/runs/${encodeURIComponent(item.id)}/events?${query}`);
  const table = element("table"); const head = element("tr");
  ["Sequence", "Timestamp", "Event", "Component", "Evidence"].forEach(label => head.appendChild(element("th", label)));
  const thead = element("thead"); thead.appendChild(head); table.appendChild(thead);
  const body = element("tbody");
  page.items.forEach(event => {
    const row = element("tr");
    [event.sequence, event.timestamp, event.event_type, event.source_component].forEach(value => row.appendChild(element("td", value)));
    const cell = element("td"); const button = element("button", "Open evidence"); button.type = "button";
    button.addEventListener("click", () => showEvent(item.id, event.event_id, returnAction).catch(showError));
    cell.appendChild(button); row.appendChild(cell); body.appendChild(row);
  });
  table.appendChild(body); section.appendChild(table);
  pager(section, page, nextOffset => renderRunTimeline(item, nextOffset, filters, returnAction));
  form.addEventListener("submit", event => {
    event.preventDefault();
    renderRunTimeline(item, 0, {trace: trace.value, type: type.value}, returnAction).catch(showError);
  });
  view.appendChild(section);
}

async function renderNested(item, collection, name, offset, renderItem) {
  const id = `nested-${name}`; let host = document.getElementById(id);
  if (!host) { host = element("section"); host.id = id; view.appendChild(host); }
  host.replaceChildren(element("h3", name.replaceAll("-", " ")));
  const page = await request(`/api/v1/${collection}/${encodeURIComponent(item.id)}/${name}?offset=${offset}&limit=50`);
  if (page.items.length === 0) host.appendChild(element("p", `No ${name.replaceAll("-", " ")} recorded.`));
  page.items.forEach((value, index) => renderItem(host, value, page.offset + index));
  pager(host, page, nextOffset => renderNested(item, collection, name, nextOffset, renderItem));
}

async function renderInvestigation(item, data) {
  const sourceId = data.catalog_source_id; view.appendChild(dataTable(data));
  const returnAction = () => showDetail("investigations", item);
  await renderNested(item, "investigations", "alerts", 0, (host, alert) => {
    const card = element("article", undefined, "card");
    card.appendChild(element("h4", `${alert.rule_id} v${alert.rule_version} · ${alert.severity}`));
    card.appendChild(element("p", alert.description));
    (alert.evidence || []).forEach(reference => card.appendChild(evidenceButton(sourceId, reference, returnAction)));
    host.appendChild(card);
  });
  await renderNested(item, "investigations", "incidents", 0, (host, incident) => {
    const card = element("article", undefined, "card");
    card.appendChild(element("h4", `${incident.severity} · ${incident.status} · ${incident.outcome.outcome}`));
    card.appendChild(element("p", incident.root_cause_hypothesis));
    (incident.timeline || []).forEach(entry => card.appendChild(evidenceButton(sourceId, entry.evidence, returnAction)));
    host.appendChild(card);
  });
  await renderNested(item, "investigations", "rule-evaluations", 0, (host, value) => host.appendChild(dataTable(value, "Rule evaluation")));
}

async function renderEvaluation(item, data) {
  view.appendChild(dataTable(data));
  await renderNested(item, "evaluations", "metrics", 0, (host, value) => host.appendChild(dataTable(value, "Metric")));
  await renderNested(item, "evaluations", "children", 0, (host, child) => {
    const className = child.assertion_passed ? "card" : "card failure";
    const card = element("article", undefined, className);
    card.appendChild(element("h4", `${child.case_id} · trial ${child.trial} · ${child.profile}`));
    card.appendChild(element("p", `Status: ${child.status}; assertion: ${child.assertion_passed ? "passed" : "failed"}`));
    if (child.exclusion_reason) card.appendChild(element("p", `Excluded: ${child.exclusion_reason}`));
    host.appendChild(card);
  });
  for (const name of ["pairs", "confusion-counts", "timing"]) {
    await renderNested(item, "evaluations", name, 0, (host, value) => host.appendChild(dataTable(value, name)));
  }
}

async function showDetail(collection, item) {
  status.textContent = "Loading detail…";
  const detail = await request(`/api/v1/${collection}/${encodeURIComponent(item.id)}`);
  clearView(detail.summary.title, () => showCollection(collection));
  const meta = element("p");
  meta.appendChild(element("span", detail.summary.provenance, "tag"));
  meta.appendChild(element("span", detail.summary.status, "tag")); view.appendChild(meta);
  if (item.kind === "investigation") await renderInvestigation(item, detail.data);
  else if (item.kind === "evaluation") await renderEvaluation(item, detail.data);
  else view.appendChild(dataTable(detail.data));
  if (item.kind === "event_source") await renderRunTimeline(item);
  if (item.kind === "run_report" && detail.data.catalog_source_id) {
    await renderRunTimeline(
      {id: detail.data.catalog_source_id},
      0,
      {trace: "", type: ""},
      () => showDetail(collection, item),
    );
  }
  status.textContent = "Detail loaded."; document.getElementById("content").focus();
}

function itemCollection(item) {
  if (["event_source", "run_report"].includes(item.kind)) return "runs";
  if (item.kind === "rule_test") return "rule-tests";
  return `${item.kind.replaceAll("_", "-")}s`;
}

async function showCollection(collection, offset = 0) {
  status.textContent = "Loading selected artifacts…";
  const endpoint = collection === "catalog" ? "/api/v1/catalog" : `/api/v1/${collection}`;
  const page = await request(`${endpoint}?offset=${offset}&limit=50`);
  clearView(collection === "catalog" ? "Overview" : collection.replaceAll("-", " "));
  if (page.items.length === 0) {
    view.appendChild(element("p", "No artifacts of this type are selected. Add reviewed entries to the dashboard manifest and restart the dashboard."));
  } else {
    const grid = element("div", undefined, "grid");
    page.items.forEach(item => {
      const card = element("article", undefined, "card"); const button = element("button", item.title); button.type = "button";
      button.addEventListener("click", () => showDetail(itemCollection(item), item).catch(showError)); card.appendChild(button);
      const meta = element("p");
      [item.kind, item.status, item.provenance].forEach(value => meta.appendChild(element("span", value, "tag")));
      card.appendChild(meta); grid.appendChild(card);
    });
    view.appendChild(grid);
  }
  pager(view, page, nextOffset => showCollection(collection, nextOffset));
  status.textContent = `${page.total} selected artifact${page.total === 1 ? "" : "s"}.`;
}

function showError(error) {
  clearView("Unable to load view");
  view.appendChild(element("p", error instanceof Error ? error.message : "Request failed"));
  status.textContent = "The requested view is unavailable.";
}

back.addEventListener("click", () => { if (backAction) Promise.resolve(backAction()).catch(showError); });
document.querySelectorAll("nav button").forEach(button => {
  button.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach(item => item.removeAttribute("aria-current"));
    button.setAttribute("aria-current", "page"); showCollection(button.dataset.view).catch(showError);
  });
});

document.querySelector("nav button").setAttribute("aria-current", "page");
showCollection("catalog").catch(showError);
