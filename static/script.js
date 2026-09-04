let lastResult = null;

const LEVEL_COLOR = {
  LOW: "var(--safe)",
  MEDIUM: "var(--medium)",
  HIGH: "var(--high)",
  CRITICAL: "var(--critical)",
};

function esc(x) {
  return String(x ?? "").replace(/[&<>"']/g, m => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[m]));
}

function setStatus(msg, spinning) {
  const status = document.getElementById("status");
  status.innerHTML = spinning ? `<span class="spinner"></span>${esc(msg)}` : esc(msg);
}

function showError(msg) {
  document.getElementById("result").innerHTML =
    `<div class="error-banner">${esc(msg)}</div>`;
}

async function analyze() {
  const btn = document.getElementById("analyzeBtn");
  const fileInput = document.getElementById("file");
  const emailText = document.getElementById("email").value;
  const scanbar = document.getElementById("scanbar");

  if (!fileInput.files[0] && !emailText.trim()) {
    setStatus("Choose a file or paste an email first.", false);
    return;
  }

  btn.disabled = true;
  document.getElementById("result-panel")?.classList.add("is-scanning");
  setStatus("Analyzing…", true);
  if (scanbar) scanbar.hidden = false;

  const fd = new FormData();
  if (fileInput.files[0]) fd.append("file", fileInput.files[0]);
  else fd.append("email", emailText);

  try {
    const r = await fetch("/analyze", { method: "POST", body: fd });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "Analysis failed");
    lastResult = d;
    render(d);
    setStatus("Analysis complete.", false);
    loadHistory();
  } catch (e) {
    setStatus("", false);
    showError(e.message || "Something went wrong.");
  } finally {
    btn.disabled = false;
    document.getElementById("result-panel")?.classList.remove("is-scanning");
    if (scanbar) scanbar.hidden = true;
  }
}

async function loadSample() {
  const btn = document.getElementById("loadSampleBtn");
  try {
    btn.disabled = true;
    const r = await fetch("/static/sample_suspicious.eml");
    const text = await r.text();
    document.getElementById("email").value = text;
    document.getElementById("file").value = "";
    document.getElementById("filelabel").textContent = "Drop an .eml file here, or click to browse";
    setStatus("Sample loaded — press Analyze message.", false);
  } catch {
    setStatus("Could not load the sample file.", false);
  } finally {
    btn.disabled = false;
  }
}

const GAUGE_R = 42, GAUGE_C = 2 * Math.PI * GAUGE_R;

function gaugeSvg(score, level) {
  const color = LEVEL_COLOR[level] || "var(--accent)";
  return `
    <div class="gauge">
      <svg viewBox="0 0 104 104" width="104" height="104">
        <circle class="gauge-track" cx="52" cy="52" r="${GAUGE_R}"></circle>
        <circle class="gauge-value" cx="52" cy="52" r="${GAUGE_R}"
          stroke="${color}" stroke-dasharray="${GAUGE_C}" stroke-dashoffset="${GAUGE_C}"></circle>
      </svg>
      <div class="gauge-label"><b data-target="${Math.max(0, Math.min(100, score))}">0</b><span>/ 100</span></div>
    </div>`;
}

function animateGauge(container) {
  const circle = container.querySelector(".gauge-value");
  const numEl = container.querySelector(".gauge-label b");
  if (!circle || !numEl) return;
  const target = Number(numEl.dataset.target || 0);
  const finalOffset = GAUGE_C * (1 - target / 100);
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (reduceMotion) {
    circle.style.strokeDashoffset = finalOffset;
    numEl.textContent = target;
    return;
  }

  requestAnimationFrame(() => {
    circle.style.strokeDashoffset = finalOffset;
  });

  const duration = 700;
  const start = performance.now();
  function tick(now) {
    const p = Math.min(1, (now - start) / duration);
    numEl.textContent = Math.round(target * p);
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function authChips(auth) {
  const checks = auth?.checks || {};
  const order = ["spf", "dkim", "dmarc"];
  const chips = order.map(k => {
    const v = checks[k] || "not available";
    const cls = v === "pass" ? "auth-pass" : v === "fail" ? "auth-fail" : "auth-unknown";
    return `<div class="auth-chip ${cls}"><span class="dot"></span>${k.toUpperCase()}: ${esc(v)}</div>`;
  }).join("");
  return `<div class="auth-chips">${chips}</div>
    ${auth?.note ? `<p class="auth-note">${esc(auth.note)}</p>` : ""}`;
}

function render(d) {
  const r = d.risk || {};
  const level = (r.level || "LOW").toUpperCase();

  const urls = (d.threat_intelligence?.urls || []).map(x => `
    <li class="ioc-item">
      <div class="ioc-main">${esc(x.url)}</div>
      <div class="ioc-flags ${x.suspicious ? 'danger' : 'good'}">
        ${x.suspicious ? '⚠ ' + esc(x.flags.join(", ")) : '✓ No major URL flags'}
      </div>
    </li>`).join("") || "<p class='empty-line'>No links found in this message.</p>";

  const ips = (d.threat_intelligence?.ips || []).map(x => `
    <li class="ioc-item">
      <div class="ioc-main">${esc(x.ip)}</div>
      <div class="ioc-flags">${esc(x.type)}${x.reverse_dns ? ' — ' + esc(x.reverse_dns) : ''}</div>
    </li>`).join("") || "<p class='empty-line'>No IP addresses found.</p>";

  const atts = (d.attachments || []).map(a => `
    <li class="ioc-item">
      <div class="ioc-main">${esc(a.filename)}</div>
      <div class="ioc-flags ${a.suspicious_extension ? 'danger' : ''}">
        ${esc(a.content_type)}${a.suspicious_extension ? ' — ⚠ suspicious file type' : ''}
      </div>
    </li>`).join("") || "<p class='empty-line'>No attachments.</p>";

  const reasons = (r.reasons || []).map(x => `<li>${esc(x)}</li>`).join("")
    || "<li>No major risk reasons — message looks clean by this heuristic set.</li>";

  document.getElementById("result").innerHTML = `
    <div class="result-top" style="--ri:0s">
      ${gaugeSvg(r.score ?? 0, level)}
      <div class="result-top-meta">
        <span class="level-chip level-${level}">${esc(level)}</span>
        <p class="ml-line"><b>AI baseline:</b> ${esc(d.ml?.label || "Unknown")} · ${Math.round((d.ml?.probability || 0) * 100)}% confidence</p>
      </div>
    </div>

    <div class="result-section" style="--ri:.05s">
      <h4>Message</h4>
      <dl class="meta-grid">
        <dt>From</dt><dd>${esc(d.sender || "—")}</dd>
        <dt>Reply-To</dt><dd>${esc(d.reply_to || "—")}</dd>
        <dt>Subject</dt><dd>${esc(d.subject || "—")}</dd>
        <dt>SHA-256</dt><dd>
          <div class="hash-row">
            <span class="hash-text">${esc(d.sha256 || "—")}</span>
            ${d.sha256 ? `<button class="copy-btn" type="button" onclick="copyHash(this,'${esc(d.sha256)}')" aria-label="Copy SHA-256 hash"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="9" y="9" width="12" height="12" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M5 15V5a2 2 0 0 1 2-2h10" stroke="currentColor" stroke-width="1.8"/></svg><span class="tip">Copied</span></button>` : ""}
          </div>
        </dd>
      </dl>
    </div>

    <div class="result-section" style="--ri:.1s">
      <h4>Why this score</h4>
      <ul class="reason-list">${reasons}</ul>
    </div>

    <div class="result-section" style="--ri:.15s">
      <h4>Authentication</h4>
      ${authChips(d.authentication)}
    </div>

    <div class="result-section" style="--ri:.2s">
      <h4>URLs (${(d.threat_intelligence?.urls || []).length})</h4>
      <ul class="ioc-list">${urls}</ul>
    </div>

    <div class="result-section" style="--ri:.25s">
      <h4>IP addresses (${(d.threat_intelligence?.ips || []).length})</h4>
      <ul class="ioc-list">${ips}</ul>
    </div>

    <div class="result-section" style="--ri:.3s">
      <h4>Attachments (${(d.attachments || []).length})</h4>
      <ul class="ioc-list">${atts}</ul>
    </div>

    <div class="result-actions" style="--ri:.35s">
      <button class="btn btn-primary btn-small" onclick="downloadReport()">Download forensic report</button>
      <button class="btn btn-ghost btn-small" onclick="downloadJson()">Export JSON</button>
    </div>`;

  const gaugeEl = document.querySelector("#result .gauge");
  if (gaugeEl) animateGauge(gaugeEl);
}

function copyHash(btn, text) {
  navigator.clipboard?.writeText(text).then(() => {
    btn.classList.add("copied");
    setTimeout(() => btn.classList.remove("copied"), 1400);
  }).catch(() => {});
}

async function downloadReport() {
  if (!lastResult) return;
  try {
    const r = await fetch("/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(lastResult)
    });
    if (!r.ok) throw new Error("Could not generate report.");
    const b = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(b);
    a.download = "email-forensic-report.html";
    a.click();
  } catch (e) {
    setStatus(e.message, false);
  }
}

function downloadJson() {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "email-analysis.json";
  a.click();
}

function severityColor(level) {
  return LEVEL_COLOR[(level || "").toUpperCase()] || "var(--text-dim)";
}

async function loadHistory() {
  try {
    const r = await fetch("/api/history");
    const d = await r.json();
    document.getElementById("history").innerHTML = d.length
      ? `<div class="log-table">${d.map((x, i) => {
          const level = (x.level || "LOW").toUpperCase();
          const color = severityColor(level);
          return `
        <div class="log-row" style="--ri:${Math.min(i, 8) * 0.04}s">
          <span class="log-severity" style="color:${color};background:${color}1a;border:1px solid ${color}55">${esc(level)}</span>
          <div class="log-main">
            <b>${esc(x.subject || "(no subject)")}</b>
            <span class="log-sub">${esc(x.sender || "unknown sender")} · ${esc(new Date(x.created_at).toLocaleString())}</span>
          </div>
          <span class="log-score">${x.risk}/100</span>
          <div class="log-actions">
            <button class="btn-link" onclick="viewHistory(${x.id})">View</button>
            <button class="btn-link danger" onclick="deleteHistory(${x.id})">Delete</button>
          </div>
        </div>`;
        }).join("")}</div>`
      : "<div class='log-empty'>No analyses stored yet — run one above to populate the log.</div>";
  } catch {
    document.getElementById("history").innerHTML = "<div class='log-empty'>Could not load history.</div>";
  }
}

async function viewHistory(id) {
  try {
    const r = await fetch(`/api/history/${id}`);
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "Not found");
    lastResult = d;
    render(d);
    document.getElementById("console").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    setStatus(e.message, false);
  }
}

async function deleteHistory(id) {
  if (!confirm("Delete this analysis?")) return;
  try {
    await fetch(`/api/history/${id}`, { method: "DELETE" });
    loadHistory();
  } catch (e) {
    setStatus(e.message, false);
  }
}

function setupDropzone() {
  const zone = document.getElementById("dropzone");
  const input = document.getElementById("file");
  const label = document.getElementById("filelabel");

  zone.addEventListener("click", () => input.click());
  zone.addEventListener("keydown", e => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
  });
  input.addEventListener("change", () => {
    label.textContent = input.files[0] ? input.files[0].name : "Drop an .eml file here, or click to browse";
  });
  ["dragenter", "dragover"].forEach(evt =>
    zone.addEventListener(evt, e => { e.preventDefault(); zone.classList.add("dragover"); }));
  ["dragleave", "drop"].forEach(evt =>
    zone.addEventListener(evt, e => { e.preventDefault(); zone.classList.remove("dragover"); }));
  zone.addEventListener("drop", e => {
    if (e.dataTransfer.files[0]) {
      input.files = e.dataTransfer.files;
      label.textContent = e.dataTransfer.files[0].name;
    }
  });
}

function setupNavToggle() {
  const toggle = document.getElementById("navToggle");
  const nav = document.getElementById("statusbarNav");
  if (!toggle || !nav) return;
  toggle.addEventListener("click", () => {
    const open = nav.classList.toggle("mobile-open");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  });
  nav.addEventListener("click", e => {
    if (e.target.tagName === "A") {
      nav.classList.remove("mobile-open");
      toggle.setAttribute("aria-expanded", "false");
    }
  });
}

function setupScrollFx() {
  const bar = document.querySelector("#scrollProgress span");
  const topBtn = document.getElementById("backToTop");
  function onScroll() {
    const h = document.documentElement;
    const scrolled = h.scrollTop;
    const max = h.scrollHeight - h.clientHeight;
    if (bar) bar.style.width = `${max > 0 ? (scrolled / max) * 100 : 0}%`;
    if (topBtn) topBtn.classList.toggle("visible", scrolled > 480);
  }
  document.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
  topBtn?.addEventListener("click", () => window.scrollTo({ top: 0, behavior: "smooth" }));
}

function setupReveal() {
  const targets = document.querySelectorAll(".reveal");
  if (!targets.length) return;
  if (!("IntersectionObserver" in window)) {
    targets.forEach(el => el.classList.add("in-view"));
    return;
  }
  const io = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add("in-view");
        io.unobserve(entry.target);
      }
    });
  }, { threshold: 0.15, rootMargin: "0px 0px -40px 0px" });
  targets.forEach(el => io.observe(el));
}

function setupCountUp() {
  const targets = document.querySelectorAll(".count-up");
  if (!targets.length) return;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function run(el) {
    const target = Number(el.dataset.count || 0);
    if (reduceMotion || target === 0) { el.textContent = target; return; }
    const duration = 900;
    const start = performance.now();
    function tick(now) {
      const p = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(target * eased);
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  if (!("IntersectionObserver" in window)) {
    targets.forEach(run);
    return;
  }
  const io = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) { run(entry.target); io.unobserve(entry.target); }
    });
  }, { threshold: 0.6 });
  targets.forEach(el => io.observe(el));
}

function setupTypedKicker() {
  const el = document.getElementById("typedKicker");
  if (!el) return;
  const text = "Email threat & forensics console";
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    el.textContent = text;
    return;
  }
  let i = 0;
  (function type() {
    el.textContent = text.slice(0, i);
    i++;
    if (i <= text.length) setTimeout(type, 22);
  })();
}

function setupSpotlight() {
  document.querySelectorAll(".panel.spotlight").forEach(panel => {
    panel.addEventListener("mousemove", e => {
      const rect = panel.getBoundingClientRect();
      panel.style.setProperty("--mx", `${e.clientX - rect.left}px`);
      panel.style.setProperty("--my", `${e.clientY - rect.top}px`);
    });
  });
}


function setupProMotion() {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduceMotion) return;

  // Lightweight pointer tilt for feature cards — disabled on touch devices.
  if (window.matchMedia("(pointer:fine)").matches) {
    document.querySelectorAll(".pipeline-steps li, .coverage-card").forEach(card => {
      card.addEventListener("pointermove", e => {
        const r = card.getBoundingClientRect();
        const x = (e.clientX - r.left) / r.width - .5;
        const y = (e.clientY - r.top) / r.height - .5;
        card.style.transform = `translateY(-5px) perspective(700px) rotateX(${(-y * 3).toFixed(2)}deg) rotateY(${(x * 3).toFixed(2)}deg)`;
      });
      card.addEventListener("pointerleave", () => {
        card.style.transform = "";
      });
    });
  }

  // Small tactile ripple on buttons/links.
  document.addEventListener("click", e => {
    const btn = e.target.closest(".btn");
    if (!btn || btn.disabled) return;
    const r = btn.getBoundingClientRect();
    const ripple = document.createElement("span");
    ripple.className = "click-ripple";
    ripple.style.left = `${e.clientX - r.left}px`;
    ripple.style.top = `${e.clientY - r.top}px`;
    btn.appendChild(ripple);
    setTimeout(() => ripple.remove(), 550);
  });
}

function setupDropzoneMotion() {
  const zone = document.getElementById("dropzone");
  if (!zone || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  zone.addEventListener("dragover", () => zone.classList.add("drag-active"));
  zone.addEventListener("dragleave", () => zone.classList.remove("drag-active"));
  zone.addEventListener("drop", () => zone.classList.remove("drag-active"));
}

setupDropzone();
setupNavToggle();
setupScrollFx();
setupReveal();
setupCountUp();
setupTypedKicker();
setupSpotlight();
setupProMotion();
setupDropzoneMotion();
loadHistory();
