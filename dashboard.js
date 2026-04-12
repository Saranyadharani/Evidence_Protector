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
      ctx.strokeStyle = "rgba(59, 130, 246, 0.5)"; // Blue scanner line
      ctx.setLineDash([5, 5]);
      ctx.stroke();
      ctx.restore();
    }
  },
};

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

  // REVEAL EXPORT BUTTONS
  document.getElementById("exportBtn").classList.remove("hidden");
  document.getElementById("exportCsvBtn").classList.remove("hidden");

  const tbody = document.getElementById("incidentBody");
  tbody.innerHTML =
    data.incidents
      .map((inc) => {
        const sev =
          inc.severity === "CRITICAL"
            ? "text-red-500 bg-red-500/10"
            : "text-amber-500 bg-amber-500/10";
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
  const chartParent = document.getElementById("chartParent");

  // DYNAMIC WIDTH: Gives every incident enough "breathing room" (40px per point)
  const dynamicWidth = Math.max(window.innerWidth - 100, incidents.length * 40);
  chartParent.style.width = dynamicWidth + "px";

  if (chart) chart.destroy();
  
  const threshold = parseInt(document.getElementById("threshold").value) || 60;

  // Percentage Data Mapping
  const percentageData = incidents.map((i) => {
    // 100% is top, dips down as duration increases
    const ratio = (i.duration / (threshold * 4)) * 100;
    return Math.max(0, 100 - ratio); 
  });

  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: incidents.map((i) => i.start.split(" ")[1]),
      datasets: [{
        label: 'Continuity Ratio',
        data: percentageData,
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59, 130, 246, 0.1)",
        fill: true,
        tension: 0.1, // Sharper dips are easier to read vertically
        pointRadius: incidents.length > 500 ? 0 : 2, // Hide dots for massive data to keep it clean
        pointHoverRadius: 8
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false, // Allows the 600px height to take effect
      interaction: { mode: 'index', intersect: false },
      scales: {
        y: { 
          min: 0, 
          max: 100,
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { callback: (v) => v + "%", color: '#64748b', font: { size: 11 } }
        },
        x: { 
          grid: { display: false },
          ticks: { 
            color: '#64748b',
            font: { size: 10 },
            autoSkip: true,
            maxTicksLimit: 100 // Keeps the bottom from being a wall of text
          }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(15, 23, 42, 0.9)',
          padding: 12,
          callbacks: {
            label: (ctx) => ` Integrity: ${ctx.parsed.y.toFixed(1)}%`
          }
        }
      }
    },
    plugins: [verticalLinePlugin] // Keep your blue scanner line
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
