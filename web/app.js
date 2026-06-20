// ---------- country → flag emoji ----------
// Cover every country present in the daemon's AvailableLocations list.
const FLAG = {
  "Australia": "🇦🇺", "Austria": "🇦🇹", "Belgium": "🇧🇪", "Brazil": "🇧🇷",
  "Bulgaria": "🇧🇬", "Canada": "🇨🇦", "Chile": "🇨🇱", "Czech Republic": "🇨🇿",
  "Denmark": "🇩🇰", "Finland": "🇫🇮", "France": "🇫🇷", "Germany": "🇩🇪",
  "Greece": "🇬🇷", "Hong Kong": "🇭🇰", "Hungary": "🇭🇺", "Iceland": "🇮🇸",
  "India": "🇮🇳", "Indonesia": "🇮🇩", "Ireland": "🇮🇪", "Israel": "🇮🇱",
  "Italy": "🇮🇹", "Japan": "🇯🇵", "Latvia": "🇱🇻", "Lithuania": "🇱🇹",
  "Luxembourg": "🇱🇺", "Malaysia": "🇲🇾", "Mexico": "🇲🇽", "Netherlands": "🇳🇱",
  "New Zealand": "🇳🇿", "Norway": "🇳🇴", "Philippines": "🇵🇭", "Poland": "🇵🇱",
  "Portugal": "🇵🇹", "Romania": "🇷🇴", "Serbia": "🇷🇸", "Singapore": "🇸🇬",
  "Slovakia": "🇸🇰", "Slovenia": "🇸🇮", "South Africa": "🇿🇦", "South Korea": "🇰🇷",
  "Spain": "🇪🇸", "Sweden": "🇸🇪", "Switzerland": "🇨🇭", "Taiwan": "🇹🇼",
  "Thailand": "🇹🇭", "Turkey": "🇹🇷", "Ukraine": "🇺🇦",
  "United Arab Emirates": "🇦🇪", "United Kingdom": "🇬🇧",
  "United States": "🇺🇸", "Vietnam": "🇻🇳",
};

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

let state = null;
let switching = false;

function parseLocation(loc) {
  const idx = loc.indexOf(" / ");
  if (idx < 0) return { country: loc, city: "" };
  return { country: loc.slice(0, idx), city: loc.slice(idx + 3) };
}

function flagFor(loc) {
  const { country } = parseLocation(loc);
  return FLAG[country] || "🌐";
}

// ---------- fetch + render ----------
async function fetchStatus() {
  try {
    const r = await fetch("/api/status");
    if (!r.ok) return;
    state = await r.json();
    render();
  } catch (e) { /* offline, will retry */ }
}

function render() {
  if (!state) return;
  const s = state.surfshark || {};
  const ks = state.kill_switch || {};
  const stats = state.stats || {};

  const hero = $(".hero");
  const heroFlag = $("#heroFlag");
  const heroState = $("#heroState");
  const heroLoc = $("#heroLocation");
  const heroIp = $("#heroIp");

  hero.classList.toggle("switching", switching);

  const vpnOn = !!s.toggle;
  if (switching) {
    heroState.textContent = "Switching";
    heroState.className = "hero-state switching";
  } else if (vpnOn) {
    heroState.textContent = "Connected";
    heroState.className = "hero-state on";
  } else {
    heroState.textContent = "VPN Off";
    heroState.className = "hero-state off";
  }

  const loc = s.current_location || "";
  // When the VPN is off, the cached public_ip is stale (egress is blocked
  // by gluetun's firewall, so no fresh measurement is possible). Show the
  // off-state instead of misleading the user with the old country/IP.
  if (vpnOn) {
    heroFlag.textContent = loc ? flagFor(loc) : "🌐";
    const { country, city } = parseLocation(loc);
    heroLoc.textContent = city ? `${country} · ${city}` : (country || "—");
    heroIp.textContent = stats.public_ip || "Measuring…";
  } else {
    heroFlag.textContent = "🏠";
    heroLoc.textContent = "Direct (no VPN)";
    heroIp.textContent = "Exit-node falls back to host network";
  }

  // power card
  const power = $("#powerCard");
  power.classList.toggle("on", vpnOn);
  $("#powerLabel").textContent = vpnOn ? "On" : "Off";

  // details
  const details = $("#details");
  // Routing is dynamic: the front's egress watcher swaps the policy rule
  // for exit-node traffic based on VPN state, so the description has to
  // match the actual behaviour the user observes.
  const egressLabel = vpnOn ? "Via Surfshark VPN"           : "Direct — host network";
  const egressClass = vpnOn ? "armed"                        : "alert";

  const measured = stats.last_measured
    ? new Date(stats.last_measured).toLocaleTimeString()
    : "—";
  details.innerHTML = "";
  for (const [k, v, klass] of [
    ["Public IP", vpnOn ? (stats.public_ip || "—") : "— (uses host IP)", vpnOn ? "" : ""],
    ["Egress", egressLabel, egressClass],
    ["Last update", measured, ""],
    ["Version", state.version || "—", ""],
  ]) {
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `<span class="k">${k}</span><span class="v ${klass}">${v}</span>`;
    details.appendChild(row);
  }

  renderBanners();
}

function renderBanners() {
  if (!state) return;
  const s = state.surfshark || {};
  const banners = $("#banners");
  banners.innerHTML = "";
  if (!s.toggle) {
    const b = document.createElement("div");
    b.className = "banner amber";
    b.textContent = "Surfshark off — exit-node clients see the host's real IP.";
    banners.appendChild(b);
  }
}

// ---------- location sheet ----------
function buildLocList(filter = "") {
  const ul = $("#locList");
  ul.innerHTML = "";
  const locs = (state && state.available_locations) || [];
  const current = (state && state.surfshark && state.surfshark.current_location) || "";

  const lcFilter = filter.trim().toLowerCase();
  const filtered = lcFilter
    ? locs.filter((l) => l.toLowerCase().includes(lcFilter))
    : locs;

  if (filtered.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No matches";
    ul.appendChild(li);
    return;
  }

  // group by country
  const groups = new Map();
  for (const loc of filtered) {
    const { country } = parseLocation(loc);
    if (!groups.has(country)) groups.set(country, []);
    groups.get(country).push(loc);
  }

  for (const [country, entries] of groups) {
    const hdr = document.createElement("li");
    hdr.className = "group";
    hdr.textContent = country;
    ul.appendChild(hdr);
    for (const loc of entries) {
      const { city } = parseLocation(loc);
      const li = document.createElement("li");
      li.className = "item" + (loc === current ? " current" : "");
      li.innerHTML = `
        <span class="flag">${flagFor(loc)}</span>
        <span class="lbl">${city || country}</span>
        <span class="check">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
        </span>`;
      li.addEventListener("click", () => switchLocation(loc));
      ul.appendChild(li);
    }
  }
}

function openSheet(id) {
  $(`#${id}`).setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
}
function closeSheet(id) {
  $(`#${id}`).setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
}

// ---------- actions ----------
async function postJSON(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return r;
}

async function togglePower() {
  if (!state || switching) return;
  const next = !(state.surfshark && state.surfshark.toggle);
  showOverlay(next ? "Connecting…" : "Disconnecting…");
  switching = true;
  render();
  try {
    await postJSON("/api/surfshark/toggle", { enabled: next });
    await waitForCondition(60, () => state && state.surfshark && state.surfshark.toggle === next);
  } finally {
    switching = false;
    hideOverlay();
    fetchStatus();
  }
}

async function switchLocation(loc) {
  if (!state || switching) return;
  closeSheet("locSheet");
  showOverlay(`Connecting to ${parseLocation(loc).city || parseLocation(loc).country}…`);
  switching = true;
  render();
  try {
    await postJSON("/api/surfshark/location", { name: loc });
    // The IP takes ~10–20s to propagate; we wait until the public_ip changes
    // OR until 60s pass.
    const prevIp = (state && state.stats && state.stats.public_ip) || "";
    await waitForCondition(60, () =>
      state && state.surfshark && state.surfshark.current_location === loc
      && state.stats && state.stats.public_ip && state.stats.public_ip !== prevIp
    );
  } finally {
    switching = false;
    hideOverlay();
    fetchStatus();
  }
}

async function waitForCondition(maxSeconds, cond) {
  for (let i = 0; i < maxSeconds; i++) {
    await fetchStatus();
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

function showOverlay(text) {
  $("#overlayText").textContent = text || "Switching…";
  $("#overlay").setAttribute("aria-hidden", "false");
}
function hideOverlay() {
  $("#overlay").setAttribute("aria-hidden", "true");
}

// ---------- logs ----------
function appendLog(line) {
  const pre = $("#log");
  const ts = new Date().toISOString().slice(11, 19);
  pre.textContent += `${ts}  ${line}\n`;
  pre.scrollTop = pre.scrollHeight;
}

// ---------- SSE ----------
function startSSE() {
  const es = new EventSource("/api/events");
  es.onmessage = (e) => appendLog(e.data);
  ["status_update", "auto_failover", "all_failed", "refresh_complete"].forEach((t) => {
    es.addEventListener(t, (e) => {
      appendLog(`[${t}] ${e.data || ""}`);
      fetchStatus();
    });
  });
  es.onopen = () => $("#connDot").classList.add("live");
  es.onerror = () => $("#connDot").classList.remove("live");
}

// ---------- wire UI ----------
$("#powerCard").addEventListener("click", togglePower);
$("#locationCard").addEventListener("click", () => {
  buildLocList();
  $("#locSearch").value = "";
  openSheet("locSheet");
  setTimeout(() => $("#locSearch").focus(), 200);
});
$("#closeLoc").addEventListener("click", () => closeSheet("locSheet"));
$("#locSheet .sheet-backdrop").addEventListener("click", () => closeSheet("locSheet"));
$("#locSearch").addEventListener("input", (e) => buildLocList(e.target.value));

$("#logsBtn").addEventListener("click", () => openSheet("logsSheet"));
$("#closeLogs").addEventListener("click", () => closeSheet("logsSheet"));
$("#logsSheet .sheet-backdrop").addEventListener("click", () => closeSheet("logsSheet"));

// kickoff
fetchStatus();
startSSE();
setInterval(fetchStatus, 10_000);
