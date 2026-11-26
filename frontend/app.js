const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";
const STYLE_BY_LABEL = {
  normal: "ok",
  legitimate_growth: "ok",
  suspicious: "danger",
  inconclusive: "warn",
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(detail.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

function setBusy(busy) {
  document.querySelectorAll("button").forEach((button) => {
    button.disabled = busy;
  });
  $("local-btn").textContent = busy ? "Analizando…" : "Escanear mi PC";
}

function svgElement(tag, attributes, text) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderChart(result) {
  const svg = $("chart");
  svg.replaceChildren();
  const series = result.series || [];
  if (!series.length) return;

  const width = 640;
  const height = 220;
  const left = 34;
  const right = 12;
  const top = 10;
  const bottom = 26;
  const plotW = width - left - right;
  const plotH = height - top - bottom;
  const maxNet = Math.max(1, ...series.map((point) => point.net_out_rate));
  const x = (index) => left + (series.length === 1 ? plotW / 2 : (index * plotW) / (series.length - 1));
  const y = (value) => top + plotH - (Math.max(0, Math.min(100, value)) / 100) * plotH;

  for (const tick of [0, 25, 50, 75, 100]) {
    svg.appendChild(svgElement("line", {
      x1: left, y1: y(tick), x2: width - right, y2: y(tick),
      stroke: "#23314d", "stroke-width": 1,
    }));
    svg.appendChild(svgElement("text", {
      x: 4, y: y(tick) + 4, fill: "#7c8ba8", "font-size": 10,
    }, String(tick)));
  }

  const split = Math.floor(series.length / 2);
  svg.appendChild(svgElement("line", {
    x1: x(split), y1: top, x2: x(split), y2: top + plotH,
    stroke: "#64748b", "stroke-width": 1, "stroke-dasharray": "4 4",
  }));

  const lines = [
    { key: "cpu", color: "#34d399", scale: (point) => point.cpu },
    { key: "memory", color: "#60a5fa", scale: (point) => point.memory },
    { key: "net", color: "#fbbf24", scale: (point) => (point.net_out_rate / maxNet) * 100 },
  ];
  for (const line of lines) {
    const points = series.map((point, index) => `${x(index).toFixed(1)},${y(line.scale(point)).toFixed(1)}`);
    svg.appendChild(svgElement("polyline", {
      points: points.join(" "),
      fill: "none",
      stroke: line.color,
      "stroke-width": 2.5,
      "stroke-linejoin": "round",
    }));
    const last = series.length - 1;
    svg.appendChild(svgElement("circle", {
      cx: x(last), cy: y(line.scale(series[last])), r: 3.5, fill: line.color,
    }));
  }
}

function renderSignals(signals) {
  const container = $("signals");
  container.replaceChildren();
  for (const signal of signals || []) {
    const box = document.createElement("div");
    box.className = "signal " + (signal.delta_pct > 15 ? "up" : "flat");
    const title = document.createElement("span");
    title.textContent = signal.label;
    const value = document.createElement("b");
    const unit = signal.unit === undefined ? "%" : signal.unit;
    value.textContent = `${signal.delta_pct >= 0 ? "+" : ""}${signal.delta_pct.toFixed(0)}${unit}`;
    box.append(title, value);
    container.appendChild(box);
  }
}

function renderList(id, items) {
  const list = $(id);
  list.replaceChildren();
  for (const item of items || []) {
    const li = document.createElement("li");
    li.textContent = item;
    list.appendChild(li);
  }
}

function renderProcessFindings(items) {
  const container = $("process-findings");
  container.replaceChildren();
  $("process-meta").textContent = items.length
    ? `${items.length} proceso(s) nuevo(s) con detalle`
    : "sin procesos nuevos relevantes";
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "No aparecieron procesos nuevos con consumo o conexiones relevantes en la ventana.";
    container.appendChild(empty);
    return;
  }
  for (const item of items) {
    const row = document.createElement("div");
    row.className = "proc-row";
    const title = document.createElement("b");
    title.textContent = `${item.name} · PID ${item.pid} · CPU ${Number(item.cpu).toFixed(1)}%`;
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = `Padre: ${item.parent || "desconocido"} · IPs: ${item.external_ips.length ? item.external_ips.join(", ") : "ninguna"}`;
    const cmd = document.createElement("code");
    cmd.textContent = item.cmdline || item.exe || "sin línea de comandos visible";
    row.append(title, meta, cmd);
    if (item.expected) {
      const expected = document.createElement("span");
      expected.className = "flag expected";
      expected.textContent = `declarado como esperado${item.expected_by ? " · " + item.expected_by : ""}`;
      row.appendChild(expected);
    }
    for (const flag of item.flags || []) {
      const tag = document.createElement("span");
      tag.className = "flag";
      tag.textContent = flag;
      row.appendChild(tag);
    }
    container.appendChild(row);
  }
}

function renderPersistence(items) {
  const container = $("persistence-findings");
  container.replaceChildren();
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "Sin cambios en inicio automático ni en tareas programadas.";
    container.appendChild(empty);
    return;
  }
  for (const item of items) {
    const row = document.createElement("div");
    row.className = "persist-row";
    const title = document.createElement("b");
    title.textContent = item.kind === "run_key" ? "Inicio automático (Run)" : "Tarea programada";
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = `${item.name}${item.value ? " → " + item.value : ""}`;
    row.append(title, meta);
    container.appendChild(row);
  }
}

function renderContext(notes) {
  const list = $("context-notes");
  list.replaceChildren();
  for (const note of notes || []) {
    const li = document.createElement("li");
    li.textContent = note;
    list.appendChild(li);
  }
}

function renderBaseline(baseline) {
  const container = $("baseline-detail");
  container.replaceChildren();
  if (!baseline) {
    $("baseline-state").textContent = "sin datos";
    container.textContent = "Ejecuta un escaneo local para ver la comparación histórica.";
    return;
  }
  $("baseline-state").textContent = baseline.used ? "p95 disponible" : "historial insuficiente";
  const fields = [
    ["Muestras", baseline.sample_count],
    ["Ventana", `${baseline.window_days} días`],
    ["p95 CPU", `${baseline.cpu_p95.toFixed(1)}%`],
    ["p95 red", `${baseline.net_out_p95.toFixed(0)} B/s`],
    ["CPU vs p95", `${baseline.cpu_vs_p95_pct >= 0 ? "+" : ""}${baseline.cpu_vs_p95_pct.toFixed(0)}%`],
    ["Red vs p95", `${baseline.net_vs_p95_pct >= 0 ? "+" : ""}${baseline.net_vs_p95_pct.toFixed(0)}%`],
  ];
  for (const [label, value] of fields) {
    const box = document.createElement("div");
    const strong = document.createElement("b");
    strong.textContent = String(value);
    box.append(document.createTextNode(label + " "), strong);
    container.appendChild(box);
  }
  const note = document.createElement("p");
  note.className = "muted";
  note.textContent = baseline.note;
  container.appendChild(note);
}

function renderResult(result) {
  const style = STYLE_BY_LABEL[result.label] || "warn";
  $("verdict-badge").className = "badge " + style;
  $("verdict-badge").textContent = result.label_es;
  $("confidence").textContent = `confianza ${(result.confidence * 100).toFixed(0)}% · severidad ${result.severity}`;
  $("summary").textContent = result.summary;
  $("caveat").textContent = result.caveat;
  $("score-fill").style.width = `${Math.round(result.anomaly_score * 100)}%`;
  $("score-fill").style.background = style === "danger" ? "var(--danger)" : style === "warn" ? "var(--warn)" : "var(--ok)";
  $("score-value").textContent = result.anomaly_score.toFixed(2);
  $("chart-source").textContent = `${result.source === "local" ? "escaneo local" : result.scenario} · ${result.series.length} muestras`;
  $("analysis-meta").textContent = `${result.id} · ${new Date(result.created_at).toLocaleTimeString("es")} · ${result.model}${result.llm_used ? " + LLM" : ""}${result.persisted ? "" : " · no guardado"}`;

  renderChart(result);
  renderSignals(result.signals);
  renderList("evidence-legit", result.evidence_legitimate);
  renderList("evidence-susp", result.evidence_suspicious);
  renderList("checks", result.verifications);
  renderProcessFindings(result.process_findings || []);
  renderPersistence(result.persistence_findings || []);
  renderContext(result.context_notes || []);
  renderBaseline(result.history_baseline);
}

function renderHistory(rows) {
  const container = $("history");
  container.replaceChildren();
  const wrap = document.createElement("div");
  wrap.className = "history-wrap";
  const head = document.createElement("div");
  head.className = "history-row head";
  ["HORA", "ORIGEN", "CLASIFICACIÓN", "SCORE", "CONFIANZA"].forEach((text) => {
    const cell = document.createElement("span");
    cell.textContent = text;
    head.appendChild(cell);
  });
  wrap.appendChild(head);
  for (const row of rows) {
    const line = document.createElement("div");
    line.className = "history-row";
    const values = [
      new Date(row.created_at).toLocaleTimeString("es"),
      row.source === "local" ? "PC local" : row.scenario,
      row.label_es,
      Number(row.score).toFixed(2),
      `${Math.round(row.confidence * 100)}%`,
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("span");
      cell.textContent = value;
      if (index === 2) cell.className = "tag";
      line.appendChild(cell);
    });
    wrap.appendChild(line);
  }
  container.appendChild(wrap);
}

async function refreshHistory() {
  try {
    renderHistory(await api("/api/history?limit=8"));
  } catch (error) {
    console.error(error);
  }
}

async function refreshBaseline() {
  try {
    renderBaseline(await api("/api/baseline"));
  } catch (error) {
    console.error(error);
  }
}

async function checkHealth() {
  const pill = $("health-pill");
  try {
    const data = await api("/health");
    pill.className = "status up";
    $("health-text").textContent = `API conectada · ${data.model}${data.llm_configured ? " · LLM activo" : ""}`;
    $("model-name").textContent = data.model;
  } catch (error) {
    pill.className = "status down";
    $("health-text").textContent = "API no disponible";
  }
}

function currentProfile() {
  return $("profile-select").value;
}

function localScanBody() {
  const clamp = (value, fallback) => {
    const number = Number(value);
    return Number.isFinite(number) ? Math.max(2, Math.min(300, Math.round(number))) : fallback;
  };
  return {
    source: "local",
    profile: currentProfile(),
    baseline_seconds: clamp($("baseline-input").value, 4),
    window_seconds: clamp($("window-input").value, 4),
  };
}

async function runAnalysis(body) {
  setBusy(true);
  $("form-message").textContent = body.source === "local"
    ? "Leyendo métricas locales durante unos segundos…"
    : "Analizando escenario…";
  try {
    const result = await api("/api/analyze", { method: "POST", body: JSON.stringify(body) });
    renderResult(result);
    const base = (result.persisted
      ? "Análisis completado y guardado en el historial."
      : "Demo sintética: no se guardó en la base de datos.")
      + (result.llm_used ? " · explicación con LLM local" : "");
    $("form-message").textContent = result.warnings.length
      ? `${base} Avisos: ${result.warnings.join(" ")}`
      : base;
    document.querySelectorAll("[data-scenario]").forEach((button) => {
      button.classList.toggle("active", button.dataset.scenario === result.scenario);
    });
    await refreshHistory();
  } catch (error) {
    $("form-message").textContent = `Error: ${error.message}`;
  } finally {
    setBusy(false);
    await refreshMonitorStatus();
  }
}

async function refreshMonitorStatus() {
  try {
    const status = await api("/api/monitor/status");
    const card = document.querySelector(".monitor-card");
    card.classList.toggle("running", status.running);
    $("monitor-status").textContent = status.running
      ? `activo · ${status.samples} muestra(s) · ${status.interval_seconds}s`
      : status.samples
        ? `detenido · ${status.samples} muestra(s) acumuladas`
        : "detenido";
    $("monitor-stop").disabled = !status.running;
    $("monitor-start").disabled = status.running;
  } catch (error) {
    console.error(error);
  }
}

async function monitorAction(action) {
  const body = action === "start"
    ? {
        interval_seconds: Math.max(10, Math.min(3600, Number($("monitor-interval").value) || 60)),
        duration_minutes: Math.max(1, Math.min(180, Number($("monitor-minutes").value) || 15)),
      }
    : {};
  try {
    await api(`/api/monitor/${action}`, { method: "POST", body: JSON.stringify(body) });
    await refreshMonitorStatus();
    $("form-message").textContent = action === "start"
      ? "Monitor iniciado: acumulando muestras reales en segundo plano."
      : "Monitor detenido.";
  } catch (error) {
    $("form-message").textContent = `Error: ${error.message}`;
  }
}

async function init() {
  checkHealth();
  setInterval(checkHealth, 5000);
  refreshHistory();
  refreshBaseline();
  refreshMonitorStatus();
  setInterval(refreshMonitorStatus, 5000);

  try {
    const config = await api("/api/config");
    for (const id of ["baseline-input", "window-input"]) {
      const input = $(id);
      input.min = config.min_seconds;
      input.max = config.max_seconds;
      input.value = id === "baseline-input" ? config.baseline_seconds : config.window_seconds;
    }
    const profile = $("profile-select");
    profile.value = config.default_profile;
    for (const option of profile.options) {
      const details = config.profiles?.[option.value];
      if (details) option.textContent = details.label;
      if (option.value === config.default_profile) $("profile-hint").textContent = details?.description || "";
    }
    profile.addEventListener("change", () => {
      $("profile-hint").textContent = config.profiles?.[profile.value]?.description || "";
    });
    $("monitor-interval").value = config.monitor_interval_seconds;
    $("monitor-minutes").value = config.monitor_duration_minutes;
  } catch (error) {
    console.error(error);
  }

  try {
    const scenarios = await api("/api/scenarios");
    for (const scenario of scenarios) {
      const button = document.querySelector(`[data-scenario="${scenario.id}"]`);
      if (button) button.querySelector("span").textContent = scenario.description;
    }
  } catch (error) {
    console.error(error);
  }

  document.querySelectorAll("[data-scenario]").forEach((button) => {
    button.addEventListener("click", () => runAnalysis({
      source: "scenario", scenario: button.dataset.scenario, profile: currentProfile(),
    }));
  });
  $("local-btn").addEventListener("click", () => runAnalysis(localScanBody()));
  document.querySelectorAll("[data-preset]").forEach((button) => {
    button.addEventListener("click", () => {
      const [baseline, window] = button.dataset.preset.split(",").map(Number);
      $("baseline-input").value = baseline;
      $("window-input").value = window;
      document.querySelectorAll("[data-preset]").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
    });
  });
  $("event-btn").addEventListener("click", async () => {
    setBusy(true);
    try {
      const type = $("event-type").value;
      await api("/api/events", {
        method: "POST",
        body: JSON.stringify({
          type,
          detail: $("event-detail").value,
          duration_minutes: Math.max(1, Math.min(1440, Number($("event-duration").value) || 5)),
          expected_processes: $("event-processes").value.split(",").map((value) => value.trim()).filter(Boolean),
        }),
      });
      $("form-message").textContent = `Actividad '${type}' registrada. Escanea tu PC para ver si cambia la clasificación.`;
      $("event-detail").value = "";
      $("event-processes").value = "";
    } catch (error) {
      $("form-message").textContent = `Error: ${error.message}`;
    } finally {
      setBusy(false);
      await refreshMonitorStatus();
    }
  });
  $("monitor-start").addEventListener("click", () => monitorAction("start"));
  $("monitor-stop").addEventListener("click", () => monitorAction("stop"));
}

init();
