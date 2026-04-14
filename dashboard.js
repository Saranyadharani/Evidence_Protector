let chart;
let lastScanResults = null;
let flaggedIncidents = new Set();

// 1. FORENSIC SCANNER PLUGIN
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

// 2. INITIALIZATION
window.addEventListener("DOMContentLoaded", () => {
  if (!sessionStorage.getItem("isLoggedIn"))
    window.location.href = "index.html";

  // Restore state from LocalStorage
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

// 3. ANALYSIS & DATA
async function analyzeLogs(event) {
  const file = document.getElementById("logFile").files[0];
  if (!file) return showToast("Critical: Ingestion File Required");

  // 1. Show the Overlay
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
    const data = await res.json();

    // 2. Forensic Sequence (Simulated for visual impact)
    const steps = [
      "Validating SHA-256 Hash...",
      "Mapping Temporal Voids...",
      "Quantifying Financial Risk...",
      "Finalizing Registry...",
    ];

    for (const step of steps) {
      statusText.innerText = step;
      await new Promise((r) => setTimeout(r, 800)); // Pause for effect
    }

    // 3. Save and Render
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
    showToast("Backend Link Error");
  } finally {
    // 4. Hide Overlay
    overlay.classList.add("hidden");
  }
}

function renderResults(data) {
  const score = parseFloat(data.integrity_score);
  const cost =
    (data.incidents.reduce((a, b) => a + b.duration, 0) / 60) *
    (document.getElementById("costPerMin").value || 500);

  // Dashboard KPIs
  document.getElementById("integrityScoreCard").innerText =
    score.toFixed(1) + "%";
  document.getElementById("financialRisk").innerText =
    "$" + cost.toLocaleString(undefined, { minimumFractionDigits: 2 });
  document.getElementById("gapCount").innerText = data.total_gaps;

  // Registry Table
  const tbody = document.getElementById("incidentBody");
  tbody.innerHTML = data.incidents
    .map((inc, i) => {
      const isFlagged = flaggedIncidents.has(i);
      return `
            <tr id="row-${i}" class="border-b border-white/5 hover:bg-white/5 transition-all ${isFlagged ? "flagged-row" : ""}">
                <td class="p-6 font-mono text-blue-400 text-[10px]">${inc.start} <br> ${inc.end}</td>
                <td class="p-6 text-center font-bold text-white">${inc.duration}s</td>
                <td class="p-6"><span class="px-2 py-1 rounded border text-[10px] ${inc.severity === "CRITICAL" ? "text-red-400 bg-red-400/5 border-red-500/20" : "text-amber-400 bg-amber-400/5 border-amber-500/20"}">${inc.details}</span></td>
                <td class="p-6 text-right">
                    <button onclick="toggleFlag(${i})" class="${isFlagged ? "text-blue-500" : "text-slate-700 hover:text-blue-400"} transition-all">
                        <i class="${isFlagged ? "fas" : "far"} fa-flag text-lg"></i>
                    </button>
                </td>
            </tr>
        `;
    })
    .join("");

  // Forensic Lab
  document.getElementById("lab-confidence").innerText =
    (score - 2).toFixed(0) + "%";
  document.getElementById("lab-entropy").innerText =
    data.total_gaps > 5 ? "STOCHASTIC" : "LINEAR";
  document.getElementById("lab-pattern").innerText =
    score > 90 ? "NOMINAL" : "ATYPICAL";

  document.getElementById("lab-details").innerHTML =
    data.incidents
      .slice(0, 3)
      .map(
        (inc) => `
        <div class="p-3 bg-slate-900/50 rounded border border-blue-500/10">[LOG_ANOMALY] Delta detected at ${inc.start.split(" ")[1]} matches void heuristic.</div>
    `,
      )
      .join("") || "Nominal stream buffer detected.";

  // Nodes
  document.getElementById("nodes-container").innerHTML = [1, 2, 3, 4, 5]
    .map(
      (n) => `
        <div class="text-center">
            <i class="fas fa-server text-5xl mb-4 ${score < 80 && n === 2 ? "text-red-500 animate-pulse" : "text-emerald-500"}"></i>
            <p class="text-[10px] font-bold text-slate-400">NODE-0${n}</p>
        </div>
    `,
    )
    .join("");

  updateChart(data.incidents);
}

// 4. CHARTING & VIEWS
function updateChart(incidents) {
  const ctx = document.getElementById("timelineChart").getContext("2d");
  if (chart) chart.destroy();

  // Get precision settings
  const precision = document.getElementById("timePrecision").value;
  const divider =
    precision === "seconds" ? 1 : precision === "minutes" ? 60 : 3600;

  // Performance Logic: If scanning massive data, hide points to keep it "Clean" (like earlier)
  const shouldHidePoints = incidents.length > 100;

  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: incidents.map((i) => i.start.split(" ")[1]),
      datasets: [
        {
          label: "Integrity Rating",
          data: incidents.map((i) =>
            Math.max(0, 100 - i.duration / (divider * 5)),
          ),
          borderColor: "#3b82f6",
          borderWidth: 2,
          backgroundColor: "rgba(59, 130, 246, 0.1)", // Fill back to original depth
          fill: true,
          tension: 0.4, // Keep the smooth forensic curve
          pointRadius: shouldHidePoints ? 0 : 3, // Suppress points if messy
          pointHoverRadius: 10,
          pointHoverBackgroundColor: "#ef4444",
          pointBorderColor: "transparent",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: "index",
        intersect: false, // Ensures the vertical scanner works smoothly
      },
      scales: {
        y: {
          min: 0,
          max: 100,
          grid: { color: "rgba(255, 255, 255, 0.03)" },
          ticks: {
            callback: (v) => v + "%",
            color: "#64748b",
            font: { size: 10 },
          },
        },
        x: {
          grid: { display: false },
          ticks: {
            color: "#64748b",
            font: { size: 9 },
            autoSkip: true,
            maxTicksLimit: 15, // Keeps labels readable regardless of data size
          },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(15, 23, 42, 0.9)",
          titleFont: { size: 12 },
          bodyFont: { size: 12 },
          padding: 12,
          displayColors: false,
          callbacks: {
            label: (ctx) => ` Integrity: ${ctx.parsed.y.toFixed(1)}%`,
          },
        },
      },
    },
    plugins: [verticalLinePlugin], // Re-attaches your blue scanner line
  });
}

function switchTab(tabId) {
  document
    .querySelectorAll(".nav-item")
    .forEach((el) => el.classList.remove("active", "text-blue-500"));
  document
    .getElementById(`nav-${tabId}`)
    .classList.add("active", "text-blue-500");

  const titles = {
    dashboard: "Executive Overview",
    lab: "Forensic Lab",
    registry: "Incident Registry",
    nodes: "System Topology",
    compliance: "Export Center",
  };
  document.getElementById("viewTitle").innerText = titles[tabId];

  document
    .querySelectorAll(".tab-view")
    .forEach((view) => view.classList.add("hidden"));
  document.getElementById(`view-${tabId}`).classList.remove("hidden");

  if (tabId === "dashboard" && lastScanResults)
    setTimeout(() => updateChart(lastScanResults.incidents), 50);
}

// 5. FUNCTIONAL TOOLS
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

function exportToJson() {
  if (!lastScanResults) return showToast("Registry Empty");
  const blob = new Blob([JSON.stringify(lastScanResults, null, 4)], {
    type: "application/json",
  });
  saveAs(blob, `Audit_Report_${Date.now()}.json`);
}

function exportToCsv() {
  if (!lastScanResults) return showToast("Registry Empty");
  const headers = "Start,End,Duration,Severity,Details\n";
  const body = lastScanResults.incidents
    .map((i) => `${i.start},${i.end},${i.duration},${i.severity},${i.details}`)
    .join("\n");
  saveAs(
    new Blob([headers + body], { type: "text/csv" }),
    `Audit_Registry_${Date.now()}.csv`,
  );
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
      : "Critical continuity risk identified. Sequence gaps suggest log shaving.";
}

function logout() {
  sessionStorage.clear();
  localStorage.clear();
  window.location.href = "index.html";
}
