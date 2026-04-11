(function () {
  if (!sessionStorage.getItem("isLoggedIn"))
    window.location.href = "index.html";
  const navEntries = performance.getEntriesByType("navigation");
  if (navEntries.length > 0 && navEntries[0].type === "reload") {
    sessionStorage.removeItem("isLoggedIn");
    window.location.href = "index.html";
    return;
  }
  window.addEventListener("DOMContentLoaded", () => {
    const lastScan = localStorage.getItem("last_scan_time");
    if (lastScan)
      document.getElementById("lastCheckedTime").innerText = lastScan;
    document.getElementById("sessionID").innerText =
      "#" + Math.floor(Math.random() * 900 + 100);
  });
})();

let chart;
let lastScanResults = null;

function logout() {
  sessionStorage.removeItem("isLoggedIn");
  window.location.href = "index.html";
}
function updateFileName() {
  const f = document.getElementById("logFile").files[0];
  document.getElementById("fileNameDisplay").innerText = f
    ? f.name
    : "Upload Log";
}

async function analyzeLogs(event) {
  const file = document.getElementById("logFile").files[0];
  if (!file) return alert("Select evidence file first.");
  document.getElementById("scanOverlay").classList.remove("hidden");
  const formData = new FormData();
  formData.append("file", file);
  formData.append("threshold", document.getElementById("threshold").value);
  try {
    const res = await fetch("http://127.0.0.1:8000/analyze", {
      method: "POST",
      body: formData,
    });
    const data = await res.json();
    lastScanResults = data;
    const now = new Date().toLocaleString();
    localStorage.setItem("last_scan_time", now);
    document.getElementById("lastCheckedTime").innerText = now;

    const steps = [
      "Validating Hash...",
      "Mapping Temporal Voids...",
      "Running Heuristics...",
      "Finalizing Registry...",
    ];
    for (const step of steps) {
      document.getElementById("loaderStatus").innerText = step;
      await new Promise((r) => setTimeout(r, 600));
    }

    renderResults(data);
    generateAIInsights(data);
    document.getElementById("scanOverlay").classList.add("hidden");
  } catch (e) {
    alert("Backend Offline");
    document.getElementById("scanOverlay").classList.add("hidden");
  }
}

function generateAIInsights(data) {
  const content = document.getElementById("aiInsightContent");
  document.getElementById("aiInsights").classList.remove("hidden");
  const score = parseFloat(data.integrity_score);
  let insight =
    score > 95
      ? "Pattern Normal: System indicates high continuity. No signs of log-purging detected."
      : "Warning: Large temporal voids found. Anomaly detected at " +
        (data.incidents[0]?.start.split(" ")[1] || "T-Zero") +
        ".";
  content.innerHTML = `<div class="ai-insight-box">${insight}</div>`;
}

function renderResults(data) {
  document.getElementById("gaugePanel").style.opacity = "1";
  const score = parseFloat(data.integrity_score);
  document.getElementById("integrityScore").innerText = score.toFixed(1) + "%";
  document.getElementById("gaugePath").style.strokeDashoffset =
    251.2 - 251.2 * (score / 100);
  document.getElementById("gapCount").innerText = data.total_gaps;
  document.getElementById("dataSpan").innerText =
    data.incidents[0]?.start.split(" ")[0] || "N/A";
  document.getElementById("peakVoid").innerText = formatTime(
    Math.max(...data.incidents.map((i) => i.duration)),
  );

  const tbody = document.getElementById("incidentBody");
  tbody.innerHTML =
    data.incidents
      .map((inc) => {
        const sev =
          inc.severity === "CRITICAL"
            ? "text-red-500 bg-red-500/10"
            : "text-amber-500 bg-amber-500/10";
        // Restored End Time Display
        return `<tr class="border-b border-slate-800">
            <td class="p-4 font-mono text-[10px]">
              <div class="text-blue-500">S: ${inc.start}</div>
              <div class="text-slate-500">E: ${inc.end}</div>
            </td>
            <td class="p-4 text-center font-black">${formatTime(inc.duration)}</td>
            <td class="p-4 italic text-slate-500 font-bold">${inc.details}</td>
            <td class="p-4 text-right"><span class="px-2 py-0.5 rounded border ${sev}">${inc.severity}</span></td>
          </tr>`;
      })
      .join("") ||
    '<tr><td colspan="4" class="p-10 text-center text-emerald-400">✓ NO VOIDS FOUND</td></tr>';

  setTimeout(
    () =>
      document
        .querySelectorAll("#incidentBody tr")
        .forEach((r) => r.classList.add("reveal")),
    100,
  );
  updateChart(data.incidents);
  generateHeatmap(data.incidents);
}

function generateHeatmap(incidents) {
  const heatmap = document.getElementById("heatmap");
  heatmap.innerHTML = "";
  const first = new Date(incidents[0].start).getTime();
  const last = new Date(incidents[incidents.length - 1].end).getTime();
  const total = last - first;
  incidents.forEach((inc) => {
    const segment = document.createElement("div");
    segment.className = "gap-segment";
    segment.style.left =
      ((new Date(inc.start).getTime() - first) / total) * 100 + "%";
    segment.style.width =
      Math.max(
        0.5,
        ((new Date(inc.end).getTime() - new Date(inc.start).getTime()) /
          total) *
          100,
      ) + "%";
    heatmap.appendChild(segment);
  });
}

function formatTime(s) {
  return s < 60 ? s + "s" : Math.floor(s / 60) + "m " + (s % 60) + "s";
}

function updateChart(incidents) {
  const ctx = document.getElementById("timelineChart").getContext("2d");
  if (chart) chart.destroy();
  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: incidents.map((i) => i.start.split(" ")[1]),
      datasets: [
        {
          data: incidents.map((i) => i.duration),
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59, 130, 246, 0.1)",
          fill: true,
          tension: 0.4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { beginAtZero: true, grid: { color: "#1e293b" } },
        x: { grid: { display: false } },
      },
      plugins: { legend: { display: false } },
    },
  });
}

function exportToJson() {
  const blob = new Blob([JSON.stringify(lastScanResults, null, 4)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `Forensic_Report_${Date.now()}.json`;
  a.click();
}
function exportToCsv() {
  const headers = ["Start", "End", "Duration", "Detail", "Severity"];
  const rows = lastScanResults.incidents.map((i) => [
    i.start,
    i.end,
    i.duration,
    i.details,
    i.severity,
  ]);
  const content = [headers.join(","), ...rows.map((r) => r.join(","))].join(
    "\n",
  );
  const blob = new Blob([content], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `Forensic_Report_${Date.now()}.csv`;
  a.click();
}
