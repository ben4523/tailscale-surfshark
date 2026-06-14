const $ = (s) => document.querySelector(s);
let state = null;

async function fetchStatus() {
  const r = await fetch("/api/status");
  if (!r.ok) return;
  state = await r.json();
  render();
}

function render() {
  if (!state) return;
  const s = state.surfshark || {};
  const ks = state.kill_switch || {};
  const stats = state.stats || {};
  const status = $("#status");
  status.innerHTML = "";
  const fields = [
    ["Surfshark", s.toggle ? `ON (${s.current_location || "?"})` : "OFF"],
    ["Kill switch", ks.currently_armed ? "Armed" : (ks.enabled_by_env ? "Disarmed" : "Disabled")],
    ["Public IP", stats.public_ip || "—"],
    ["Last handshake", stats.wg0_last_handshake || "—"],
    ["Latency", stats.wg0_latency_ms ? stats.wg0_latency_ms + " ms" : "—"],
  ];
  for (const [k, v] of fields) {
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = v;
    status.appendChild(dt); status.appendChild(dd);
  }
  $("#toggle").checked = !!s.toggle;
  const sel = $("#location"); sel.innerHTML = "";
  for (const loc of state.available_locations || []) {
    const o = document.createElement("option");
    o.value = loc; o.textContent = loc;
    if (loc === s.current_location) o.selected = true;
    sel.appendChild(o);
  }
  const ul = $("#preferred"); ul.innerHTML = "";
  for (const p of s.preferred_locations || []) {
    const li = document.createElement("li");
    li.textContent = p; li.draggable = true;
    ul.appendChild(li);
  }
  renderBanners();
}

function renderBanners() {
  const s = state.surfshark || {};
  const ks = state.kill_switch || {};
  const banners = $("#banners"); banners.innerHTML = "";
  if (!s.toggle && !ks.enabled_by_env) {
    const b = document.createElement("div");
    b.className = "banner red";
    b.textContent = "VPN BYPASS ACTIVE — your real IP is exposed for clients using this exit node.";
    banners.appendChild(b);
  }
}

async function postJSON(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return r;
}

$("#toggle").addEventListener("change", async (e) => {
  await postJSON("/api/surfshark/toggle", { enabled: e.target.checked });
  fetchStatus();
});

$("#switch").addEventListener("click", async () => {
  await postJSON("/api/surfshark/location", { name: $("#location").value });
  fetchStatus();
});

$("#refresh").addEventListener("click", async () => {
  await postJSON("/api/surfshark/refresh", {});
});

function startSSE() {
  const es = new EventSource("/api/events");
  es.onmessage = (e) => appendLog(e.data);
  ["status_update", "auto_failover", "all_failed", "refresh_complete"].forEach((t) => {
    es.addEventListener(t, (e) => {
      appendLog(`[${t}] ${e.data}`);
      fetchStatus();
    });
  });
}

function appendLog(line) {
  const pre = $("#log");
  pre.textContent += new Date().toISOString() + "  " + line + "\n";
  pre.scrollTop = pre.scrollHeight;
}

fetchStatus();
startSSE();
setInterval(fetchStatus, 10_000);
