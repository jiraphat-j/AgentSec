"use strict";

const view = document.getElementById("view");
const title = document.getElementById("view-title");
const status = document.getElementById("status");
const back = document.getElementById("back");
let backAction = null;
let navigationVersion = 0;
let timelineRequestVersion = 0;
const nestedRequestVersions = new Map();

function beginNavigation() {
  navigationVersion += 1;
  timelineRequestVersion = 0;
  nestedRequestVersions.clear();
  return navigationVersion;
}

function isCurrentNavigation(version) {
  return version === navigationVersion;
}

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
  button.dataset.evidenceId = reference.event_id;
  button.addEventListener("click", () => showEvent(sourceId, reference.event_id, () => returnAction(reference.event_id)));
  return button;
}

async function showEvent(sourceId, eventId, returnAction) {
  const navigation = beginNavigation();
  status.textContent = "Loading exact evidence…";
  let event;
  try {
    event = await request(`/api/v1/runs/${encodeURIComponent(sourceId)}/events/${encodeURIComponent(eventId)}`);
  } catch (error) {
    if (isCurrentNavigation(navigation)) showError(error);
    return;
  }
  if (!isCurrentNavigation(navigation)) return;
  clearView(`Evidence ${event.event_id}`, returnAction);
  view.appendChild(dataTable(event));
  status.textContent = "Exact evidence loaded.";
  document.getElementById("content").focus();
}

async function renderRunTimeline(item, offset, filters, returnAction, reported, navigation, state) {
  if (!isCurrentNavigation(navigation)) return;
  const requestVersion = ++timelineRequestVersion;
  const section = element("section"); section.id = "run-timeline";
  section.appendChild(element("h3", "Sequence-ordered timeline"));
  let form; let trace; let type;
  if (!reported) {
    form = element("form", undefined, "filters");
    trace = element("input"); trace.placeholder = "Exact trace ID"; trace.value = filters.trace;
    type = element("input"); type.placeholder = "Exact event type"; type.value = filters.type;
    const apply = element("button", "Apply filters"); apply.type = "submit";
    form.append(trace, type, apply); section.appendChild(form);
  }
  const query = new URLSearchParams({offset: String(offset), limit: "50"});
  if (!reported && filters.trace) query.set("trace_id", filters.trace);
  if (!reported && filters.type) query.set("event_type", filters.type);
  const timelineName = reported ? "timeline" : "events";
  let page;
  try {
    page = await request(`/api/v1/runs/${encodeURIComponent(item.id)}/${timelineName}?${query}`);
  } catch (error) {
    if (isCurrentNavigation(navigation) && requestVersion === timelineRequestVersion) showError(error);
    return;
  }
  if (!isCurrentNavigation(navigation) || requestVersion !== timelineRequestVersion) return;
  state.timelineOffset = offset;
  state.filters = {...filters};
  const table = element("table"); const head = element("tr");
  ["Sequence", "Timestamp", "Event", "Component", "Evidence"].forEach(label => head.appendChild(element("th", label)));
  const thead = element("thead"); thead.appendChild(head); table.appendChild(thead);
  const body = element("tbody");
  page.items.forEach(event => {
    const row = element("tr");
    [event.sequence, event.timestamp, event.event_type, event.source_component].forEach(value => row.appendChild(element("td", value)));
    const cell = element("td");
    if (reported) cell.textContent = "Reported only";
    else {
      const button = element("button", "Open evidence"); button.type = "button";
      button.dataset.evidenceId = event.event_id;
      button.addEventListener("click", () => showEvent(item.id, event.event_id, () => returnAction(event.event_id)));
      cell.appendChild(button);
    }
    row.appendChild(cell); body.appendChild(row);
  });
  table.appendChild(body); section.appendChild(table);
  pager(section, page, nextOffset => renderRunTimeline(item, nextOffset, filters, returnAction, reported, navigation, state));
  if (form) form.addEventListener("submit", event => {
    event.preventDefault();
    renderRunTimeline(item, 0, {trace: trace.value, type: type.value}, returnAction, reported, navigation, state);
  });
  const old = document.getElementById("run-timeline");
  if (old) old.remove();
  view.appendChild(section);
}

async function renderNested(item, collection, name, offset, renderItem, navigation, state) {
  if (!isCurrentNavigation(navigation)) return;
  const requestVersion = (nestedRequestVersions.get(name) || 0) + 1;
  nestedRequestVersions.set(name, requestVersion);
  let page;
  try {
    page = await request(`/api/v1/${collection}/${encodeURIComponent(item.id)}/${name}?offset=${offset}&limit=50`);
  } catch (error) {
    if (isCurrentNavigation(navigation) && nestedRequestVersions.get(name) === requestVersion) showError(error);
    return;
  }
  if (!isCurrentNavigation(navigation) || nestedRequestVersions.get(name) !== requestVersion) return;
  state.nestedOffsets[name] = offset;
  const id = `nested-${name}`; let host = document.getElementById(id);
  if (!host) { host = element("section"); host.id = id; view.appendChild(host); }
  host.replaceChildren(element("h3", name.replaceAll("-", " ")));
  if (page.items.length === 0) host.appendChild(element("p", `No ${name.replaceAll("-", " ")} recorded.`));
  page.items.forEach((value, index) => renderItem(host, value, page.offset + index));
  pager(host, page, nextOffset => renderNested(item, collection, name, nextOffset, renderItem, navigation, state));
}

async function renderInvestigation(item, data, navigation, state) {
  const sourceId = data.catalog_source_id; view.appendChild(dataTable(data));
  const returnAction = evidenceId => showDetail("investigations", item, state, evidenceId);
  await renderNested(item, "investigations", "alerts", state.nestedOffsets.alerts || 0, (host, alert) => {
    const card = element("article", undefined, "card");
    card.appendChild(element("h4", `${alert.rule_id} v${alert.rule_version} · ${alert.severity}`));
    card.appendChild(element("p", alert.description));
    (alert.evidence || []).forEach(reference => card.appendChild(evidenceButton(sourceId, reference, returnAction)));
    host.appendChild(card);
  }, navigation, state);
  await renderNested(item, "investigations", "incidents", state.nestedOffsets.incidents || 0, (host, incident) => {
    const card = element("article", undefined, "card");
    card.appendChild(element("h4", `${incident.severity} · ${incident.status} · ${incident.outcome.outcome}`));
    card.appendChild(element("p", incident.root_cause_hypothesis));
    const stages = incident.stages || [];
    const chain = element("div", undefined, "attack-chain");
    chain.setAttribute("role", "img");
    chain.setAttribute("aria-label", `Recorded attack chain: ${stages.map(stage => stage.stage).join(", ") || "none"}`);
    stages.forEach((stage, index) => {
      if (index > 0) chain.appendChild(element("span", "→", "chain-arrow"));
      chain.appendChild(element("span", stage.stage.replaceAll("_", " "), "chain-stage"));
    });
    card.appendChild(chain);
    const stageTable = element("table");
    stageTable.appendChild(element("caption", "Recorded attack-chain stages and evidence"));
    const stageBody = element("tbody");
    stages.forEach(stage => {
      const row = element("tr");
      row.appendChild(element("th", stage.stage.replaceAll("_", " ")));
      const evidence = element("td");
      (stage.evidence || []).forEach(reference => evidence.appendChild(evidenceButton(sourceId, reference, returnAction)));
      row.appendChild(evidence); stageBody.appendChild(row);
    });
    stageTable.appendChild(stageBody); card.appendChild(stageTable);
    (incident.timeline || []).forEach(entry => card.appendChild(evidenceButton(sourceId, entry.evidence, returnAction)));
    const remediation = element("ul");
    (incident.recommended_remediation || []).forEach(item => remediation.appendChild(element("li", item)));
    if (remediation.children.length > 0) {
      card.appendChild(element("h5", "Recommended remediation"));
      card.appendChild(remediation);
    }
    host.appendChild(card);
  }, navigation, state);
  await renderNested(item, "investigations", "rule-evaluations", state.nestedOffsets["rule-evaluations"] || 0, (host, value) => host.appendChild(dataTable(value, "Rule evaluation")), navigation, state);
}

async function renderEvaluation(item, data, navigation, state) {
  view.appendChild(dataTable(data));
  await renderNested(item, "evaluations", "metrics", state.nestedOffsets.metrics || 0, (host, value) => {
    const card = element("article", undefined, "card");
    const fraction = value.denominator === 0 ? "Unavailable" : `${value.numerator}/${value.denominator}`;
    card.appendChild(element("h4", `${value.profile}: ${value.name.replaceAll("_", " ")}`));
    const progress = element("progress"); progress.max = 1;
    if (value.denominator !== 0 && typeof value.value === "number") progress.value = value.value;
    progress.setAttribute("aria-label", `${value.name} ${fraction}`);
    card.appendChild(progress);
    card.appendChild(dataTable(value, `Exact metric values: ${fraction}`));
    host.appendChild(card);
  }, navigation, state);
  await renderNested(item, "evaluations", "children", state.nestedOffsets.children || 0, (host, child) => {
    const className = child.assertion_passed ? "card" : "card failure";
    const card = element("article", undefined, className);
    card.appendChild(element("h4", `${child.case_id} · trial ${child.trial} · ${child.profile}`));
    card.appendChild(element("p", `Status: ${child.status}; assertion: ${child.assertion_passed ? "passed" : "failed"}`));
    if (child.exclusion_reason) card.appendChild(element("p", `Excluded: ${child.exclusion_reason}`));
    host.appendChild(card);
  }, navigation, state);
  for (const name of ["pairs", "confusion-counts", "timing"]) {
    await renderNested(item, "evaluations", name, state.nestedOffsets[name] || 0, (host, value) => host.appendChild(dataTable(value, name)), navigation, state);
  }
}

async function showDetail(collection, item, savedState = {}, restoreEvidenceId = null) {
  const navigation = beginNavigation();
  const state = {
    collectionOffset: savedState.collectionOffset || 0,
    timelineOffset: savedState.timelineOffset || 0,
    filters: savedState.filters || {trace: "", type: ""},
    nestedOffsets: savedState.nestedOffsets || {},
  };
  status.textContent = "Loading detail…";
  let detail;
  try {
    detail = await request(`/api/v1/${collection}/${encodeURIComponent(item.id)}`);
  } catch (error) {
    if (isCurrentNavigation(navigation)) showError(error);
    return;
  }
  if (!isCurrentNavigation(navigation)) return;
  clearView(detail.summary.title, () => showCollection(collection, state.collectionOffset));
  const meta = element("p");
  meta.appendChild(element("span", detail.summary.provenance, "tag"));
  meta.appendChild(element("span", detail.summary.status, "tag")); view.appendChild(meta);
  if (item.kind === "investigation") await renderInvestigation(item, detail.data, navigation, state);
  else if (item.kind === "evaluation") await renderEvaluation(item, detail.data, navigation, state);
  else view.appendChild(dataTable(detail.data));
  const returnAction = evidenceId => showDetail(collection, item, state, evidenceId);
  if (item.kind === "event_source") {
    await renderRunTimeline(item, state.timelineOffset, state.filters, returnAction, false, navigation, state);
  }
  if (item.kind === "run_report" && detail.data.catalog_source_id) {
    await renderRunTimeline(
      {id: detail.data.catalog_source_id},
      state.timelineOffset,
      state.filters,
      returnAction,
      false,
      navigation,
      state,
    );
  }
  if (item.kind === "run_report" && !detail.data.catalog_source_id) {
    await renderRunTimeline(item, state.timelineOffset, state.filters, returnAction, true, navigation, state);
  }
  if (!isCurrentNavigation(navigation)) return;
  status.textContent = "Detail loaded."; document.getElementById("content").focus();
  if (restoreEvidenceId) {
    const target = Array.from(document.querySelectorAll("[data-evidence-id]")).find(
      button => button.dataset.evidenceId === restoreEvidenceId,
    );
    if (target) target.focus();
  }
}

function itemCollection(item) {
  if (["event_source", "run_report"].includes(item.kind)) return "runs";
  if (item.kind === "rule_test") return "rule-tests";
  return `${item.kind.replaceAll("_", "-")}s`;
}

async function showCollection(collection, offset = 0) {
  const navigation = beginNavigation();
  status.textContent = "Loading selected artifacts…";
  const endpoint = collection === "catalog" ? "/api/v1/catalog" : `/api/v1/${collection}`;
  let page;
  try {
    page = await request(`${endpoint}?offset=${offset}&limit=50`);
  } catch (error) {
    if (isCurrentNavigation(navigation)) showError(error);
    return;
  }
  if (!isCurrentNavigation(navigation)) return;
  clearView(collection === "catalog" ? "Overview" : collection.replaceAll("-", " "));
  if (page.items.length === 0) {
    view.appendChild(element("p", "No artifacts of this type are selected. Add reviewed entries to the dashboard manifest and restart the dashboard."));
  } else {
    const grid = element("div", undefined, "grid");
    page.items.forEach(item => {
      const card = element("article", undefined, "card"); const button = element("button", item.title); button.type = "button";
      button.addEventListener("click", () => showDetail(itemCollection(item), item, {collectionOffset: offset})); card.appendChild(button);
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
  beginNavigation();
  clearView("Unable to load view");
  view.appendChild(element("p", error instanceof Error ? error.message : "Request failed"));
  status.textContent = "The requested view is unavailable.";
}

back.addEventListener("click", () => { if (backAction) Promise.resolve(backAction()).catch(showError); });
document.querySelectorAll("nav button").forEach(button => {
  button.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach(item => item.removeAttribute("aria-current"));
    button.setAttribute("aria-current", "page"); showCollection(button.dataset.view);
  });
});

document.querySelector("nav button").setAttribute("aria-current", "page");
showCollection("catalog");
