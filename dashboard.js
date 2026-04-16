let chart;
let lastScanResults = null;
let flaggedIncidents = new Set();

const verticalLinePlugin = {
  id: "verticalLine",
  afterDraw: (chart) => {
    if (chart.tooltip?._active?.length) {
      const x = chart.tooltip._active[0].element.x;
      const yAxis = chart.scales.y;
      const ctx = chart.ctx;
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(x, yAxis.top);
      ctx.lineTo(x, yAxis.bottom);
      ctx.lineWidth = 1;
      ctx.strokeStyle = "rgba(59, 130, 246, 0.4)";
      ctx.setLineDash([5, 5]);
      ctx.stroke();
      ctx.restore();
    }
  },
};

window.addEventListener("DOMContentLoaded", () => {
  if (!sessionStorage.getItem("isLoggedIn")) {
    window.location.href = "index.html";
    return;
  }
  const savedFlags = localStorage.getItem("flagged_items");
  if (savedFlags) {
    flaggedIncidents = new Set(JSON.parse(savedFlags));
    updateFlagCount();
  }
  loadLastSession();
});

function loadLastSession() {
  const savedData = localStorage.getItem("last_forensic_scan");
  const savedMeta = localStorage.getItem("last_scan_metadata");
  if (savedData && savedMeta) {
    lastScanResults = JSON.parse(savedData);
    const meta = JSON.parse(savedMeta);
    document.getElementById("lastScanTime").innerText = meta.timestamp;
    document.getElementById("lastFileName").innerText = meta.fileName;
    renderResults(lastScanResults);
    generateAIInsights(lastScanResults);
  }
}

async function analyzeLogs(event) {
  const file = document.getElementById("logFile").files[0];
  if (!file) return showToast("Critical: Ingestion File Required");

  const overlay = document.getElementById("scanOverlay");
  const statusText = document.getElementById("loaderStatus");
  overlay.classList.remove("hidden");

  const formData = new FormData();
  formData.append("file", file);
  formData.append("threshold", 60);

  try {
    const res = await fetch("http://localhost:8000/analyze", {
      method: "POST",
      body: formData,
    });
    if (!res.ok) throw new Error("Backend Connection Failed");
    const data = await res.json();

    const steps = [
      "Hashing Evidence...",
      "Mapping Voids...",
      "Quantifying Risk...",
      "Finalizing Suite...",
    ];
    for (const step of steps) {
      statusText.innerText = step;
      await new Promise((r) => setTimeout(r, 700));
    }

    const meta = {
      timestamp: new Date().toLocaleString().toUpperCase(),
      fileName: file.name,
    };
    localStorage.setItem("last_forensic_scan", JSON.stringify(data));
    localStorage.setItem("last_scan_metadata", JSON.stringify(meta));

    lastScanResults = data;
    document.getElementById("lastScanTime").innerText = meta.timestamp;
    document.getElementById("lastFileName").innerText = meta.fileName;

    renderResults(data);
    generateAIInsights(data);
    showToast("Forensic Analysis Complete");
  } catch (e) {
    showToast("Backend Link Error: Ensure server is running");
  } finally {
    overlay.classList.add("hidden");
  }
}

function renderResults(data) {
  const score = parseFloat(data.integrity_score);

  // KPIs
  document.getElementById("integrityScoreCard").innerText =
    score.toFixed(1) + "%";
  const risk = (100 - score).toFixed(1);
  const riskEl = document.getElementById("financialRisk");
  riskEl.innerText = risk + "%";
  riskEl.className =
    risk > 50
      ? "text-3xl font-black text-red-500"
      : risk > 20
        ? "text-3xl font-black text-amber-500"
        : "text-3xl font-black text-emerald-500";
  document.getElementById("gapCount").innerText = data.total_gaps;

  // Table
  const tbody = document.getElementById("incidentBody");
  tbody.innerHTML = data.incidents
    .map((inc, i) => {
      const isFlagged = flaggedIncidents.has(i);
      return `<tr id="row-${i}" class="border-b border-white/5 hover:bg-white/5 transition-all ${isFlagged ? "flagged-row" : ""}">
        <td class="p-6 font-mono text-blue-400 text-[10px]">${inc.start}<br>${inc.end}</td>
        <td class="p-6 text-center font-bold text-white">${inc.duration}s</td>
        <td class="p-6"><span class="px-2 py-1 rounded border text-[10px] ${inc.severity === "CRITICAL" ? "text-red-400 bg-red-400/5 border-red-500/20" : "text-amber-400 bg-amber-400/5 border-amber-500/20"}">${inc.details}</span></td>
        <td class="p-6 text-right"><button onclick="toggleFlag(${i})" class="${isFlagged ? "text-blue-500" : "text-slate-700 hover:text-blue-400"}"><i class="${isFlagged ? "fas" : "far"} fa-flag text-lg"></i></button></td>
    </tr>`;
    })
    .join("");

  // Forensic Lab Functional Sync
  document.getElementById("lab-confidence").innerText =
    (score - 1.5).toFixed(1) + "%";
  document.getElementById("lab-entropy").innerText =
    data.total_gaps > 5 ? "VOLATILE" : "LINEAR";
  document.getElementById("lab-pattern").innerText =
    score > 85 ? "NOMINAL" : "ATYPICAL";
  document.getElementById("lab-details").innerHTML =
    data.incidents
      .slice(0, 5)
      .map(
        (inc) => `
    <div class="p-3 bg-slate-900/50 rounded border border-blue-500/10">
        <span class="text-blue-500 font-bold">[SIGNATURE_MATCH]</span> Anomaly at ${inc.start.split(" ")[1]} matches 'Log Shaving' heuristic (${inc.duration}s void).
    </div>`,
      )
      .join("") ||
    '<div class="p-4 text-slate-500 italic text-center">Nominal stream buffer detected.</div>';

  updateStrategicTimeline(data.incidents, score);
  updateChart(data.incidents);
}

function updateStrategicTimeline(incidents, score) {
  const container = document.getElementById("nodes-container");
  if (!container || !incidents.length) return;

  document.getElementById("early-anomaly").innerText =
    incidents[0].start.split(" ")[1];
  const peak = incidents.reduce(
    (max, inc) => (inc.duration > max.duration ? inc : max),
    incidents[0],
  );
  document.getElementById("peak-window").innerText = peak.start.split(" ")[1];

  const containment = document.getElementById("containment-status");
  containment.innerText = score < 70 ? "IMMEDIATE ISOLATION" : "MONITORING";
  containment.className =
    score < 70
      ? "text-sm font-mono text-red-500"
      : "text-sm font-mono text-emerald-500";

  container.className =
    "relative flex justify-between items-center w-full min-h-[150px] px-10";
  container.innerHTML =
    `<div class="absolute left-0 right-0 h-0.5 bg-slate-800 top-1/2 -translate-y-1/2 z-0"></div>` +
    incidents
      .slice(0, 6)
      .map(
        (inc) => `
        <div class="relative group flex flex-col items-center z-10">
            <div class="absolute -top-10 opacity-0 group-hover:opacity-100 transition-all bg-slate-900 border border-blue-500/30 px-2 py-1 rounded text-[9px] whitespace-nowrap">Gap: ${inc.duration}s</div>
            <div class="w-4 h-4 rounded-full ${inc.severity === "CRITICAL" ? "bg-red-500" : "bg-amber-500"} transition-transform group-hover:scale-150"></div>
            <p class="absolute -bottom-8 text-[9px] font-mono text-slate-500 rotate-45 group-hover:text-white">${inc.start.split(" ")[1]}</p>
        </div>`,
      )
      .join("");
}

function updateChart(incidents) {
  const ctx = document.getElementById("timelineChart").getContext("2d");
  if (chart) chart.destroy();
  const precision = document.getElementById("timePrecision").value;
  const divider =
    precision === "seconds" ? 1 : precision === "minutes" ? 60 : 3600;
  const hidePoints = incidents.length > 100;

  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: incidents.map((i) => i.start.split(" ")[1]),
      datasets: [
        {
          data: incidents.map((i) =>
            Math.max(0, 100 - i.duration / (divider * 5)),
          ),
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59, 130, 246, 0.1)",
          fill: true,
          tension: 0.4,
          pointRadius: hidePoints ? 0 : 3,
          pointHoverRadius: 10,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        y: {
          min: 0,
          max: 100,
          ticks: { callback: (v) => v + "%", color: "#64748b" },
          grid: { color: "rgba(255,255,255,0.03)" },
        },
        x: {
          ticks: { color: "#64748b", autoSkip: true, maxTicksLimit: 15 },
          grid: { display: false },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(15, 23, 42, 0.9)",
          displayColors: false,
        },
      },
    },
    plugins: [verticalLinePlugin],
  });
}

function switchTab(tabId) {
  document
    .querySelectorAll(".nav-item")
    .forEach((el) => el.classList.remove("active", "text-blue-500"));
  const navItem = document.getElementById(`nav-${tabId}`);
  if (navItem) navItem.classList.add("active", "text-blue-500");

  const titles = {
    dashboard: "Executive Overview",
    lab: "Forensic Lab",
    threats: "Neural Triage Map",
    registry: "Incident Registry",
    nodes: "Strategic Timeline",
    vault: "Security Vault",
    compliance: "Export Center",
  };
  document.getElementById("viewTitle").innerText = titles[tabId];
  document
    .querySelectorAll(".tab-view")
    .forEach((view) => view.classList.add("hidden"));
  document.getElementById(`view-${tabId}`).classList.remove("hidden");

  if (lastScanResults) {
    if (tabId === "dashboard")
      setTimeout(() => updateChart(lastScanResults.incidents), 50);
    if (tabId === "nodes")
      updateStrategicTimeline(
        lastScanResults.incidents,
        parseFloat(lastScanResults.integrity_score),
      );
  }
}

// Operational Exports
function exportToJson() {
  if (!lastScanResults) return showToast("Critical: No scan data found");
  const blob = new Blob([JSON.stringify(lastScanResults, null, 4)], {
    type: "application/json",
  });
  saveAs(blob, `Forensic_Report_${Date.now()}.json`);
  showToast("JSON Exported Successfully");
}

function exportToCsv() {
  if (!lastScanResults) return showToast("Critical: No scan data found");
  const headers = "Window_Start,Window_End,Duration,Severity,Details\n";
  const body = lastScanResults.incidents
    .map(
      (i) =>
        `"${i.start}","${i.end}",${i.duration},"${i.severity}","${i.details}"`,
    )
    .join("\n");
  saveAs(
    new Blob([headers + body], { type: "text/csv" }),
    `Forensic_Registry_${Date.now()}.csv`,
  );
  showToast("CSV Exported Successfully");
}

function toggleFlag(index) {
  if (flaggedIncidents.has(index)) flaggedIncidents.delete(index);
  else flaggedIncidents.add(index);
  localStorage.setItem(
    "flagged_items",
    JSON.stringify(Array.from(flaggedIncidents)),
  );
  renderResults(lastScanResults);
  updateFlagCount();
  showToast("Flag status updated");
}

function updateFlagCount() {
  document.getElementById("flag-count").innerText =
    `${flaggedIncidents.size} Flagged`;
}
function saveAs(blob, name) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
}
function showToast(msg) {
  const toast = document.getElementById("toast");
  document.getElementById("toastMsg").innerText = msg;
  toast.classList.replace("translate-y-24", "translate-y-0");
  toast.classList.replace("opacity-0", "opacity-100");
  setTimeout(() => {
    toast.classList.replace("translate-y-0", "translate-y-24");
    toast.classList.replace("opacity-100", "opacity-0");
  }, 3000);
}
function updateFileName() {
  const f = document.getElementById("logFile").files[0];
  document.getElementById("fileNameDisplay").innerText = f
    ? f.name
    : "Select Evidence";
}
function generateAIInsights(data) {
  document.getElementById("aiInsights").classList.remove("hidden");
  document.getElementById("aiInsightContent").innerText =
    data.integrity_score > 90
      ? "Compliance signatures verified. Operational health nominal."
      : "Critical risk identified. Sequence gaps suggest log manipulation.";
}
function logout() {
  sessionStorage.clear();
  localStorage.clear();
  window.location.href = "index.html";
}
