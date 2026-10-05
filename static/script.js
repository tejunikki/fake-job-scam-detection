// ---------------------------------------------------------------------------
// Demo example messages
// ---------------------------------------------------------------------------
const DEMO_EXAMPLES = {
  safe: "Thank you for interviewing for the Software Trainee position at TechNova Solutions. We are pleased to invite you for a final round interview with the engineering team next Thursday at 10 AM at our office. Please bring a copy of your resume and a valid ID. If selected, the formal offer letter and salary details will be shared through our official HR portal at careers.technova.com. No fees are required at any stage of our hiring process.",
  suspicious: "Congratulations! You have been shortlisted for a Work From Home Data Entry job with a monthly salary of ₹60,000. To confirm your seat, please pay a refundable registration fee of ₹1500 and join our Telegram group for further instructions. Limited seats available, please respond quickly.",
  high_risk: "URGENT!! You have WON the Customer Support Executive position with a joining bonus of ₹95,000!! To claim your bonus, send your bank account number, OTP and PIN immediately to this link: http://job-payout.tk/claim. Offer expires in 1 hour, act now or lose this opportunity forever!!!",
};

const jobText = document.getElementById("jobText");
const analyzeBtn = document.getElementById("analyzeBtn");
const errorMsg = document.getElementById("errorMsg");
const placeholderState = document.getElementById("placeholderState");
const resultState = document.getElementById("resultState");

let indicatorChart = null;

document.querySelectorAll("[data-demo]").forEach((btn) => {
  btn.addEventListener("click", () => {
    jobText.value = DEMO_EXAMPLES[btn.dataset.demo];
    jobText.focus();
  });
});

analyzeBtn.addEventListener("click", async () => {
  const text = jobText.value.trim();
  hideError();

  if (!text) {
    showError("Please paste a job offer message before analyzing.");
    return;
  }

  setLoading(true);
  try {
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    const data = await res.json();

    if (!res.ok) {
      showError(data.error || "Something went wrong. Please try again.");
      return;
    }
    renderResult(data);
  } catch (err) {
    showError("Could not reach the analysis service. Please check that the app is running.");
  } finally {
    setLoading(false);
  }
});

function setLoading(isLoading) {
  analyzeBtn.disabled = isLoading;
  analyzeBtn.textContent = isLoading ? "Analyzing..." : "Analyze Job Offer";
}

function showError(msg) {
  errorMsg.textContent = msg;
  errorMsg.hidden = false;
}
function hideError() {
  errorMsg.hidden = true;
  errorMsg.textContent = "";
}

function renderResult(data) {
  placeholderState.hidden = true;
  resultState.hidden = false;

  // Gauge
  const circumference = 2 * Math.PI * 52;
  const offset = circumference - (data.risk_score / 100) * circumference;
  const gaugeFill = document.getElementById("gaugeFill");
  gaugeFill.style.strokeDasharray = circumference;
  gaugeFill.style.strokeDashoffset = offset;
  gaugeFill.style.stroke =
    data.risk_band_key === "high" ? "var(--danger)" :
    data.risk_band_key === "moderate" ? "var(--moderate)" : "var(--success)";

  document.getElementById("riskScoreNum").textContent = data.risk_score;

  const bandTag = document.getElementById("riskBandTag");
  bandTag.textContent = data.risk_band;
  bandTag.className = "risk-tag " + data.risk_band_key;

  document.getElementById("predictionText").textContent = data.prediction;
  document.getElementById("confidenceText").textContent =
    data.confidence !== null && data.confidence !== undefined ? data.confidence + "%" : "N/A";

  document.getElementById("actionBox").textContent = data.recommended_action;

  // Indicator cards
  const cardsWrap = document.getElementById("indicatorCards");
  cardsWrap.innerHTML = "";
  if (data.indicators.length === 0) {
    cardsWrap.innerHTML = `<div class="indicator-card none">✓ No major scam indicators were detected in this message.</div>`;
  } else {
    data.indicators.forEach((ind) => {
      const card = document.createElement("div");
      card.className = "indicator-card";
      card.innerHTML = `
        <div class="ind-top">
          <span class="ind-label">⚠ ${escapeHtml(ind.label)}</span>
          <span class="ind-weight">+${ind.weight}</span>
        </div>
        <div class="ind-match">"${escapeHtml(ind.matches[0])}"${ind.matches.length > 1 ? ` +${ind.matches.length - 1} more` : ""}</div>
      `;
      cardsWrap.appendChild(card);
    });
  }

  // Indicator breakdown chart
  renderIndicatorChart(data.indicators);

  // Highlighted text
  document.getElementById("highlightedText").innerHTML = data.highlighted_html;

  // Link analysis
  const linkWrap = document.getElementById("linkAnalysis");
  linkWrap.innerHTML = "";
  if (data.links.length === 0) {
    linkWrap.innerHTML = `<div class="mini-item">No links found in this message.</div>`;
  } else {
    linkWrap.innerHTML = `<div class="mini-item">${data.links.length} link(s) found.</div>`;
    data.links.forEach((l) => {
      const flags = [];
      if (!l.https) flags.push('<span class="flag-warn">No HTTPS</span>');
      if (l.suspicious_tld) flags.push('<span class="flag-warn">Unusual domain ending</span>');
      if (l.shortener) flags.push('<span class="flag-warn">Link shortener</span>');
      if (flags.length === 0) flags.push('<span class="flag-ok">No obvious flags</span>');
      const item = document.createElement("div");
      item.className = "mini-item";
      item.innerHTML = `<strong>${escapeHtml(l.domain || l.url)}</strong><br>${flags.join(" · ")}`;
      linkWrap.appendChild(item);
    });
  }

  // Contact analysis
  const contactWrap = document.getElementById("contactAnalysis");
  const c = data.contacts;
  contactWrap.innerHTML = `
    <div class="mini-item">Emails found: <strong>${c.email_count}</strong></div>
    <div class="mini-item">Phone numbers found: <strong>${c.phone_count}</strong></div>
    ${c.email_domains.map(d => `<div class="mini-item">Domain: <strong>${escapeHtml(d.domain)}</strong> ${d.is_free_provider ? '<span class="flag-warn">Free/personal email provider</span>' : '<span class="flag-ok">Custom domain</span>'}</div>`).join("")}
  `;

  // Safety tips
  const tipsWrap = document.getElementById("safetyTips");
  tipsWrap.innerHTML = "";
  data.safety_tips.forEach((tip) => {
    const li = document.createElement("li");
    li.textContent = tip;
    tipsWrap.appendChild(li);
  });

  // History
  renderHistory(data.history);

  resultState.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderIndicatorChart(indicators) {
  const ctx = document.getElementById("indicatorChart").getContext("2d");
  const labels = indicators.map((i) => i.label);
  const weights = indicators.map((i) => i.weight);

  if (indicatorChart) {
    indicatorChart.destroy();
  }
  if (indicators.length === 0) {
    return;
  }
  indicatorChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Contribution to risk score",
        data: weights,
        backgroundColor: "#1F2A44",
        borderRadius: 6,
        maxBarThickness: 34,
      }],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, max: 30, grid: { color: "#EDEFF3" } },
        y: { grid: { display: false } },
      },
    },
  });
}

function renderHistory(history) {
  const body = document.getElementById("historyBody");
  body.innerHTML = "";
  if (!history || history.length === 0) {
    body.innerHTML = `<tr><td colspan="3" class="muted">No messages analyzed yet this session.</td></tr>`;
    return;
  }
  history.forEach((item) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(item.time)}</td>
      <td>${escapeHtml(item.prediction)}</td>
      <td><span class="risk-dot risk-${item.risk_band_key}"></span>${item.risk_score}/100</td>
    `;
    body.appendChild(tr);
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}