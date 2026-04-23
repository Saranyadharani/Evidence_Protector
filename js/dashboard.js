/**
 * EVIDENCE PROTECTOR PRO - CORE DASHBOARD LOGIC
 * Features: Automated Archiving, Session Persistence, Forensic Exports, Dynamic Search, Flag All, Log File Previewer
 */

// ─── STATE & CONSTANTS ───────────────────────────────────────────────────────
let chart = null;
let lastScanResults = null;
let flaggedIncidents = new Set();
let currentLogContent = null; // Store current log file content for preview
const CASES_KEY = "forensic_cases";

// ─── INITIALIZATION ──────────────────────────────────────────────────────────
window.addEventListener("DOMContentLoaded", () => {
  // 1. Unified Authentication Check - BYPASSED FOR TESTING
  if (!localStorage.getItem("access_token")) {
    localStorage.setItem("access_token", "test_bypass_" + Date.now());
    sessionStorage.setItem("isLoggedIn", "true");
  }
  
  const hasAuth =
    !!localStorage.getItem("access_token") ||
    !!sessionStorage.getItem("isLoggedIn");
  if (!hasAuth) {
    window.location.href = "index.html";
    return;
  }

  // 2. Restore Flagged Items
  const savedFlags = localStorage.getItem("flagged_items");
  if (savedFlags) {
    try {
      flaggedIncidents = new Set(JSON.parse(savedFlags));
      updateFlagCount();
    } catch (e) {
      console.warn("Flag restoration failed");
    }
  }

  // 3. UI Bootstrap
  updateGreeting();
  updateCaseBadge();
  loadLastSession();
  initDropZone();
  setupSelectAllCheckbox();
  initFilePreviewListener(); // Initialize file preview listener

  // 4. API Monitoring
  checkApiStatus();
  setInterval(checkApiStatus, 5000);

  // 5. Reactive Scroll-To-Top (dashboard scrolls inside #mainScroll)
  initScrollToTop();
});

// ─── LOG FILE PREVIEWER (Issue #71) ──────────────────────────────────────────
function initFilePreviewListener() {
  const fileInput = document.getElementById("logFile");
  const previewBtn = document.getElementById("previewBtn");
  
  if (!fileInput) {
    console.error("File input not found");
    return;
  }
  
  // Function to enable/disable preview button based on file selection
  function updatePreviewButtonState() {
    const previewBtn = document.getElementById("previewBtn");
    const fileNameDisplay = document.getElementById("fileNameDisplay");
    
    if (fileInput.files.length > 0) {
      const file = fileInput.files[0];
      if (previewBtn) {
        previewBtn.disabled = false;
        previewBtn.classList.remove("opacity-50", "cursor-not-allowed");
        console.log("Preview button ENABLED for file:", file.name);
      }
      if (fileNameDisplay) {
        fileNameDisplay.innerText = file.name;
      }
      
      // Read file content for preview
      const reader = new FileReader();
      reader.onload = function(event) {
        currentLogContent = event.target.result;
        console.log("File loaded for preview, size:", currentLogContent.length, "bytes");
      };
      reader.onerror = function(error) {
        console.error("Error reading file:", error);
        showToast("Error reading file");
      };
      reader.readAsText(file);
    } else {
      if (previewBtn) {
        previewBtn.disabled = true;
        previewBtn.classList.add("opacity-50", "cursor-not-allowed");
        console.log("Preview button DISABLED - no file selected");
      }
      currentLogContent = null;
    }
  }
  
  // Listen for file selection
  fileInput.addEventListener("change", function(e) {
    console.log("File selected:", e.target.files[0]?.name || "none");
    updatePreviewButtonState();
  });
  
  // Also listen for clicks on the drop area label
  const dropArea = document.getElementById("dropArea");
  if (dropArea) {
    dropArea.addEventListener("click", function() {
      // Small delay to allow file selection to complete
      setTimeout(updatePreviewButtonState, 100);
    });
  }
  
  // Initial check (in case file was already selected)
  updatePreviewButtonState();
}

function previewLogFile() {
  console.log("Preview button clicked");
  const previewBox = document.getElementById("previewBox");
  const previewContent = document.getElementById("previewContent");
  
  if (!currentLogContent) {
    console.log("No file content available");
    showToast("No log file loaded. Please select a file first.");
    return;
  }
  
  console.log("Previewing file, content length:", currentLogContent.length);
  
  // Get first 10 lines
  const lines = currentLogContent.split('\n');
  const first10Lines = lines.slice(0, 10);
  
  // Display with line numbers
  let numberedContent = '';
  for (let i = 0; i < first10Lines.length; i++) {
    const lineNumber = (i + 1).toString().padStart(3, ' ');
    const escapedLine = escapeHtml(first10Lines[i] || ' ');
    numberedContent += `<span class="text-slate-500 select-none font-mono">${lineNumber}</span> | ${escapedLine}\n`;
  }
  
  // If file has more than 10 lines, show indicator
  if (lines.length > 10) {
    numberedContent += `\n<span class="text-slate-600">...</span> <span class="text-slate-500">(+${lines.length - 10} more lines)</span>`;
  }
  
  previewContent.innerHTML = numberedContent;
  previewBox.classList.remove("hidden");
  previewBox.classList.add("block");
  
  showToast("Preview loaded - First 10 lines displayed");
}

function closePreview() {
  const previewBox = document.getElementById("previewBox");
  if (previewBox) {
    previewBox.classList.add("hidden");
    previewBox.classList.remove("block");
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ─── SESSION PERSISTENCE ─────────────────────────────────────────────────────
function loadLastSession() {
  const savedData = localStorage.getItem("last_forensic_scan");
  const savedMeta = localStorage.getItem("last_scan_metadata");

  if (savedData && savedMeta) {
    try {
      lastScanResults = JSON.parse(savedData);
      const meta = JSON.parse(savedMeta);

      const timeEl = document.getElementById("lastScanTime");
      const fileEl = document.getElementById("lastFileName");
      if (timeEl) timeEl.innerText = meta.timestamp;
      if (fileEl) fileEl.innerText = meta.fileName;

      renderResults(lastScanResults);
    } catch (e) {
      console.error("Session restoration failed", e);
    }
  }
}

// ─── ANALYSIS & AUTO-ARCHIVING ───────────────────────────────────────────────
async function analyzeLogs(event) {
  if (event) event.preventDefault();
  const fileInput = document.getElementById("logFile");
  const file = fileInput.files[0] || fileInput._droppedFile;

  if (!file) {
    document.getElementById("dropArea")?.classList.add("border-red-500/50");
    return showToast("Critical: No source file selected");
  }

  const overlay = document.getElementById("scanOverlay");
  const statusText = document.getElementById("loaderStatus");
  overlay.classList.remove("hidden");

  const formData = new FormData();
  formData.append("file", file);
  const thresholdValue = document.getElementById("thresholdInput")?.value || 60;
  formData.append("threshold", thresholdValue);

  try {
    const token = localStorage.getItem("access_token");
    const res = await fetch("http://localhost:8000/analyze", {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: formData,
    });

    if (res.status === 401) return logout();
    const data = await res.json();

    statusText.innerText = "Finalizing Reports...";
    await new Promise((r) => setTimeout(r, 600));

    const meta = {
      timestamp: new Date().toLocaleString().toUpperCase(),
      fileName: file.name,
    };
    localStorage.setItem("last_forensic_scan", JSON.stringify(data));
    localStorage.setItem("last_scan_metadata", JSON.stringify(meta));

    saveToVault(data, file.name);

    lastScanResults = data;
    renderResults(data);
    showToast("Analysis Finalized — Case Archived");
  } catch (e) {
    showToast("Backend Link Error");
    console.error("Analysis error:", e);
  } finally {
    overlay.classList.add("hidden");
  }
}

// ─── VAULT & HISTORY LOGIC ───────────────────────────────────────────────────
function saveToVault(data, fileName) {
  const cases = JSON.parse(localStorage.getItem(CASES_KEY) || "[]");
  const newCase = {
    id: `FS-${Date.now()}-${Math.random().toString(36).substr(2, 4).toUpperCase()}`,
    name: fileName,
    timestamp: new Date().toISOString(),
    integrityScore: parseFloat(data.integrity_score),
    totalGaps: data.total_gaps,
    incidents: data.incidents,
  };
  cases.unshift(newCase);
  if (cases.length > 50) cases.pop();
  localStorage.setItem(CASES_KEY, JSON.stringify(cases));
  updateCaseBadge();
}

function renderCaseHistory() {
  const cases = JSON.parse(localStorage.getItem(CASES_KEY) || "[]");
  const tbody = document.getElementById("caseHistoryBody");
  const emptyState = document.getElementById("caseHistoryEmpty");
  const clearBtn = document.getElementById("clearVaultBtn");

  if (!tbody) return;
  if (clearBtn) clearBtn.disabled = cases.length === 0;

  if (cases.length === 0) {
    tbody.innerHTML = "";
    emptyState?.classList.remove("hidden");
    return;
  }

  emptyState?.classList.add("hidden");
  tbody.innerHTML = cases
    .map(
      (c) => `
        <tr class="border-b border-white/5 hover:bg-white/5 transition-all">
            <td class="p-6">
                <div class="text-white font-bold text-xs">${escapeHtml(c.name)}</div>
                <div class="text-[9px] text-slate-600 font-mono">${c.id}</div>
            </td>
            <td class="p-6 text-[10px] text-slate-400 font-mono">${new Date(c.timestamp).toLocaleString()}</td>
            <td class="p-6 text-center">
                <span class="px-2 py-1 rounded text-[10px] font-black ${c.integrityScore > 80 ? "bg-emerald-500/10 text-emerald-500" : "bg-red-500/10 text-red-500"}">
                    ${c.integrityScore.toFixed(1)}%
                </span>
            </td>
            <td class="p-6 text-right">
                <button onclick="loadCase('${c.id}')" class="text-blue-500 hover:text-blue-400 mr-4 text-[10px] font-bold uppercase">Load</button>
                <button onclick="deleteCase('${c.id}')" class="text-slate-600 hover:text-red-500"><i class="fas fa-trash-can"></i></button>
            </td>
         </tr>`,
    )
    .join("");
}

function loadCase(caseId) {
  const cases = JSON.parse(localStorage.getItem(CASES_KEY) || "[]");
  const found = cases.find((c) => c.id === caseId);
  if (found) {
    lastScanResults = {
      incidents: found.incidents,
      integrity_score: found.integrityScore,
      total_gaps: found.totalGaps,
    };
    renderResults(lastScanResults);
    switchTab("dashboard");
    showToast("Historical Case Loaded");
  }
}

function deleteCase(caseId) {
  let cases = JSON.parse(localStorage.getItem(CASES_KEY) || "[]");
  cases = cases.filter((c) => c.id !== caseId);
  localStorage.setItem(CASES_KEY, JSON.stringify(cases));
  updateCaseBadge();
  renderCaseHistory();
  showToast("Case Deleted");
}

function clearAllHistory() {
  if (confirm("🚨 Wipe all historical cases? This cannot be undone.")) {
    localStorage.setItem(CASES_KEY, "[]");
    updateCaseBadge();
    renderCaseHistory();
    showToast("Vault Wiped");
  }
}

// ─── REGISTRY SEARCH & SORT ──────────────────────────────────────────────────
function filterRegistry() {
  const term = document.getElementById("searchInput")?.value.toLowerCase();
  const noMatchMsg = document.getElementById("noMatchMessage");
  const tableBody = document.getElementById("incidentBody");

  if (!lastScanResults) return;

  const filtered = lastScanResults.incidents.filter(
    (inc) =>
      inc.start.toLowerCase().includes(term) ||
      inc.duration.toString().includes(term),
  );

  if (filtered.length === 0) {
    tableBody.innerHTML = "";
    noMatchMsg?.classList.remove("hidden");
  } else {
    noMatchMsg?.classList.add("hidden");
    updateRegistryTable(filtered);
  }
}

function handleSortChange(criteria) {
  if (!lastScanResults) return showToast("No data to sort");
  const placeholder = document.getElementById("sortPlaceholder");
  if (criteria === "high")
    lastScanResults.incidents.sort((a, b) => b.duration - a.duration);
  else if (criteria === "low")
    lastScanResults.incidents.sort((a, b) => a.duration - b.duration);
  if (placeholder) placeholder.disabled = true;
  updateRegistryTable(lastScanResults.incidents);
}

// ─── FLAG ALL FUNCTIONALITY ───────────────────────────────────────────────────
function setupSelectAllCheckbox() {
  const selectAllCheckbox = document.getElementById('selectAllCheckbox');
  if (!selectAllCheckbox) return;
  selectAllCheckbox.removeEventListener('change', handleSelectAll);
  selectAllCheckbox.addEventListener('change', handleSelectAll);
}

function handleSelectAll(e) {
  const isChecked = e.target.checked;

  if (!lastScanResults || !lastScanResults.incidents) {
    showToast("No incidents to flag");
    e.target.checked = false;
    return;
  }

  if (isChecked) {
    for (let i = 0; i < lastScanResults.incidents.length; i++) {
      flaggedIncidents.add(i);
    }
    showToast(`Flagged all ${lastScanResults.incidents.length} incidents`);
  } else {
    flaggedIncidents.clear();
    showToast("Cleared all flags");
  }

  localStorage.setItem("flagged_items", JSON.stringify(Array.from(flaggedIncidents)));
  updateFlagCount();
  updateRegistryTable(lastScanResults.incidents);

  const selectAllCheckbox = document.getElementById('selectAllCheckbox');
  if (selectAllCheckbox && selectAllCheckbox.checked !== isChecked) {
    selectAllCheckbox.checked = isChecked;
  }
}

function handleIndividualCheckboxChange(e) {
  const checkbox = e.target;
  const index = parseInt(checkbox.getAttribute('data-index'));

  if (checkbox.checked) {
    flaggedIncidents.add(index);
  } else {
    flaggedIncidents.delete(index);
  }

  localStorage.setItem("flagged_items", JSON.stringify(Array.from(flaggedIncidents)));

  const flagButton = checkbox.closest('tr').querySelector(`button[onclick="toggleFlag(${index})"]`);
  if (flagButton) {
    if (checkbox.checked) {
      flagButton.classList.add('text-blue-500');
      flagButton.classList.remove('text-slate-700');
    } else {
      flagButton.classList.remove('text-blue-500');
      flagButton.classList.add('text-slate-700');
    }
  }

  updateFlagCount();
  updateSelectAllCheckboxState();
}

function updateSelectAllCheckboxState() {
  const selectAllCheckbox = document.getElementById('selectAllCheckbox');
  if (!selectAllCheckbox || !lastScanResults || !lastScanResults.incidents) return;

  const totalIncidents = lastScanResults.incidents.length;
  const flaggedCount = flaggedIncidents.size;

  if (totalIncidents === 0) {
    selectAllCheckbox.checked = false;
    selectAllCheckbox.indeterminate = false;
  } else if (flaggedCount === totalIncidents) {
    selectAllCheckbox.checked = true;
    selectAllCheckbox.indeterminate = false;
  } else if (flaggedCount > 0 && flaggedCount < totalIncidents) {
    selectAllCheckbox.checked = false;
    selectAllCheckbox.indeterminate = true;
  } else {
    selectAllCheckbox.checked = false;
    selectAllCheckbox.indeterminate = false;
  }
}

// ─── CHART & IMAGE EXPORTS ────────────────────────────────────────────────────
function updateChart(incidents) {
  const canvas = document.getElementById("timelineChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (chart) chart.destroy();

  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: incidents.map((i) => i.start.split(" ")[1] || i.start),
      datasets: [
        {
          label: "Integrity",
          data: incidents.map((i) => Math.max(0, 100 - i.duration / 300)),
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59,130,246,0.1)",
          fill: true,
          tension: 0.4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { min: 0, max: 100, ticks: { color: "#64748b" } },
        x: { ticks: { color: "#64748b", maxTicksLimit: 10 } },
      },
      plugins: {
        legend: { display: false },
        zoom: {
          zoom: { wheel: { enabled: true }, mode: "x" },
          pan: { enabled: true, mode: "x" },
        },
      },
    },
  });
}

function exportChartAsPNG() {
  if (!chart) return showToast("No chart data");
  const a = document.createElement("a");
  a.download = `Chart_${Date.now()}.png`;
  a.href = chart.canvas.toDataURL("image/png");
  a.click();
}

function exportChartAsJPG() {
  if (!chart) return showToast("No chart data");
  const canvas = chart.canvas;
  const tmp = document.createElement("canvas");
  tmp.width = canvas.width;
  tmp.height = canvas.height;
  const ctx = tmp.getContext("2d");
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, tmp.width, tmp.height);
  ctx.drawImage(canvas, 0, 0);
  const a = document.createElement("a");
  a.download = `Chart_${Date.now()}.jpg`;
  a.href = tmp.toDataURL("image/jpeg", 0.9);
  a.click();
}

// ─── EXPORT CENTER ───────────────────────────────────────────────────────────
function exportForensicJSON() {
  if (!lastScanResults) return showToast("No data available");
  const blob = new Blob([JSON.stringify(lastScanResults, null, 4)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `Forensic_Report_${Date.now()}.json`;
  a.click();
  showToast("JSON Exported");
}

function exportRegistryCSV() {
  if (!lastScanResults) return showToast("Registry empty");
  let csv = "Start,End,Duration\n";
  lastScanResults.incidents.forEach((i) => (csv += `${i.start},${i.end},${i.duration}\n`));
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `Registry_${Date.now()}.csv`;
  a.click();
  showToast("CSV Exported");
}

// ─── UI & NAVIGATION UTILS ───────────────────────────────────────────────────
function switchTab(tabId) {
  document.querySelectorAll(".nav-item").forEach((el) => el.classList.remove("active", "text-blue-500"));
  document.getElementById(`nav-${tabId}`)?.classList.add("active", "text-blue-500");
  document.querySelectorAll(".tab-view").forEach((v) => v.classList.add("hidden"));
  document.getElementById(`view-${tabId}`)?.classList.remove("hidden");

  if (tabId === "history") renderCaseHistory();
  if (tabId === "dashboard" && lastScanResults)
    setTimeout(() => updateChart(lastScanResults.incidents), 50);
}

function updateCaseBadge() {
  const badge = document.getElementById("case-count-badge");
  const count = JSON.parse(localStorage.getItem(CASES_KEY) || "[]").length;
  if (badge) badge.innerText = count;
}

function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("sidebarOverlay");
  sidebar.classList.toggle("-translate-x-full");
  overlay.classList.toggle("hidden");
}

function showToast(msg) {
  const toast = document.getElementById("toast");
  const msgEl = document.getElementById("toastMsg");
  if (!toast || !msgEl) return;
  msgEl.innerText = msg;
  toast.classList.remove("translate-y-24", "opacity-0");
  toast.classList.add("translate-y-0", "opacity-100");
  setTimeout(() => {
    toast.classList.add("translate-y-24", "opacity-0");
    toast.classList.remove("translate-y-0", "opacity-100");
  }, 3000);
}

function initDropZone() {
  const dropArea = document.getElementById("dropArea");
  const fileInput = document.getElementById("logFile");
  if (!dropArea || !fileInput) return;
  
  // Handle click on drop area
  dropArea.addEventListener("click", (e) => {
    if (e.target !== fileInput && !fileInput.contains(e.target)) {
      fileInput.click();
    }
  });
  
  // Handle file selection
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      const fileName = fileInput.files[0].name;
      const fileNameDisplay = document.getElementById("fileNameDisplay");
      if (fileNameDisplay) fileNameDisplay.innerText = fileName;
      
      // Read file for preview
      const reader = new FileReader();
      reader.onload = function(event) {
        currentLogContent = event.target.result;
        console.log("File loaded via drop zone, size:", currentLogContent.length);
      };
      reader.readAsText(fileInput.files[0]);
      
      // Enable preview button
      const previewBtn = document.getElementById("previewBtn");
      if (previewBtn) {
        previewBtn.disabled = false;
        previewBtn.classList.remove("opacity-50", "cursor-not-allowed");
      }
      
      showToast(`File loaded: ${fileName}`);
    }
  });
  
  // Drag and drop handlers
  dropArea.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropArea.classList.add("border-blue-500");
  });
  
  dropArea.addEventListener("dragleave", () => {
    dropArea.classList.remove("border-blue-500");
  });
  
  dropArea.addEventListener("drop", (e) => {
    e.preventDefault();
    dropArea.classList.remove("border-blue-500");
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      const fileName = fileInput.files[0].name;
      const fileNameDisplay = document.getElementById("fileNameDisplay");
      if (fileNameDisplay) fileNameDisplay.innerText = fileName;
      
      // Read file for preview
      const reader = new FileReader();
      reader.onload = function(event) {
        currentLogContent = event.target.result;
        console.log("File loaded via drag-drop, size:", currentLogContent.length);
      };
      reader.readAsText(fileInput.files[0]);
      
      // Enable preview button
      const previewBtn = document.getElementById("previewBtn");
      if (previewBtn) {
        previewBtn.disabled = false;
        previewBtn.classList.remove("opacity-50", "cursor-not-allowed");
      }
      
      showToast(`File loaded: ${fileName}`);
    }
  });
}

function updateGreeting() {
  const el = document.getElementById("userGreeting");
  if (!el) return;
  const hour = new Date().getHours();
  el.innerText = `${hour < 12 ? "Good Morning" : hour < 18 ? "Good Afternoon" : "Good Evening"}, Operator`;
}

function logout() {
  localStorage.removeItem("access_token");
  sessionStorage.clear();
  window.location.href = "index.html";
}

function showTOS() {
  const modal = document.getElementById("tosModal");
  if (modal) {
    modal.classList.remove("hidden");
    modal.classList.add("flex");
  }
}

function closeTOS() {
  const modal = document.getElementById("tosModal");
  if (modal) {
    modal.classList.add("hidden");
    modal.classList.remove("flex");
  }
}

async function checkApiStatus() {
  const indicator = document.getElementById("apiStatusIndicator");
  if (!indicator) return;
  try {
    const res = await fetch("http://localhost:8000/", { method: "GET" });
    indicator.className = res.ok ? "status-indicator online" : "status-indicator offline";
  } catch {
    indicator.className = "status-indicator offline";
  }
}

function renderResults(data) {
  if (!data) return;
  document.getElementById("integrityScoreCard").innerText = parseFloat(data.integrity_score).toFixed(1) + "%";
  document.getElementById("financialRisk").innerText = (100 - parseFloat(data.integrity_score)).toFixed(1) + "%";
  document.getElementById("gapCount").innerText = data.total_gaps;
  updateRegistryTable(data.incidents);
  updateChart(data.incidents);
}

function updateRegistryTable(incidents) {
  const tbody = document.getElementById("incidentBody");
  if (!tbody) return;

  tbody.innerHTML = incidents
    .map(
      (inc, i) => `
        <tr class="border-b border-white/5 hover:bg-white/5 transition-all">
            <td class="p-6 w-10">
                <input type="checkbox" class="incident-checkbox rounded border-slate-600 bg-slate-800 text-blue-500 focus:ring-blue-500 focus:ring-offset-0" data-index="${i}" ${flaggedIncidents.has(i) ? 'checked' : ''} />
            </td>
            <td class="p-6 text-blue-400 font-mono text-[10px]">${escapeHtml(inc.start)} → ${escapeHtml(inc.end)}</td>
            <td class="p-6 text-center font-bold text-white">${inc.duration}s</td>
            <td class="p-6 text-right">
                <button onclick="toggleFlag(${i})" class="${flaggedIncidents.has(i) ? "text-blue-500" : "text-slate-700"}">
                    <i class="fas fa-flag"></i>
                </button>
            </td>
          </tr>`,
    )
    .join("");

  const checkboxes = document.querySelectorAll('.incident-checkbox');
  checkboxes.forEach(checkbox => {
    checkbox.removeEventListener('change', handleIndividualCheckboxChange);
    checkbox.addEventListener('change', handleIndividualCheckboxChange);
  });

  updateSelectAllCheckboxState();
}

function toggleFlag(index) {
  if (flaggedIncidents.has(index)) {
    flaggedIncidents.delete(index);
  } else {
    flaggedIncidents.add(index);
  }

  localStorage.setItem("flagged_items", JSON.stringify(Array.from(flaggedIncidents)));

  const checkbox = document.querySelector(`.incident-checkbox[data-index="${index}"]`);
  if (checkbox) checkbox.checked = flaggedIncidents.has(index);

  updateFlagCount();
  updateSelectAllCheckboxState();

  if (lastScanResults) updateRegistryTable(lastScanResults.incidents);
}

function updateFlagCount() {
  const el = document.getElementById("flag-count");
  if (el) el.innerText = `${flaggedIncidents.size} Flagged`;
}

// ─── REACTIVE SCROLL TO TOP (DASHBOARD) ──────────────────────────────────────
function initScrollToTop() {
  const btn = document.getElementById("scrollTopBtn");
  const ring = document.getElementById("scrollProgressRing");
  const scrollContainer = document.getElementById("mainScroll");
  if (!btn || !scrollContainer) return;

  const CIRCUMFERENCE = 119.38;
  const SHOW_THRESHOLD = 300;

  function updateScrollBtn() {
    const scrollTop = scrollContainer.scrollTop;
    const scrollHeight = scrollContainer.scrollHeight - scrollContainer.clientHeight;
    const scrollPct = scrollHeight > 0 ? scrollTop / scrollHeight : 0;

    if (scrollTop > SHOW_THRESHOLD) {
      btn.classList.add("visible");
    } else {
      btn.classList.remove("visible");
    }

    if (ring) {
      const offset = CIRCUMFERENCE - scrollPct * CIRCUMFERENCE;
      ring.style.strokeDashoffset = offset;
    }
  }

  scrollContainer.addEventListener("scroll", updateScrollBtn, { passive: true });

  btn.addEventListener("click", () => {
    scrollContainer.scrollTo({ top: 0, behavior: "smooth" });
  });

  updateScrollBtn();
}