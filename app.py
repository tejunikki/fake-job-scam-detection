"""
app.py
------
Flask backend for the Fake Job Offer Scam Detector.

Routes:
    GET  /          -> renders the dashboard UI
    POST /analyze   -> accepts JSON {"text": "..."} and returns a JSON
                        analysis: ML prediction, rule-based indicators,
                        risk score, highlighted text, link/contact info,
                        safety tips and updated session history.

Security notes:
    - No eval() or exec() of user input anywhere.
    - User text is HTML-escaped before any tag is added for highlighting.
    - Only a lightweight, session-based history is kept (no permanent
      storage of raw message content).
"""

import os
import re
import html
import datetime
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify, session

from model import load_or_train_model, LABELS

app = Flask(__name__)
app.secret_key = os.environ.get("SCAM_DETECTOR_SECRET_KEY", "dev-secret-key-change-me")

# Load (or train) the ML model once at startup.
MODEL_BUNDLE = load_or_train_model()

MAX_HISTORY_ITEMS = 10
MIN_MESSAGE_LENGTH = 8  # characters


# ---------------------------------------------------------------------------
# Rule-based indicator detection
# ---------------------------------------------------------------------------
# Each indicator: (key, human label, list of regex patterns, weight)
INDICATORS = [
    (
        "payment_request",
        "Upfront payment / registration fee request",
        [
            r"registration\s*fee", r"security\s*deposit", r"processing\s*fee",
            r"pay\s+(a\s+)?(small\s+)?fee", r"pay\s*(rs\.?|₹|inr)?\s*\d+",
            r"deposit\s+(of\s+)?(rs\.?|₹|inr)?\s*\d+", r"training\s*kit",
            r"joining\s*kit", r"laptop\s*deposit", r"activation\s*charge",
            r"verification\s*charge",
        ],
        25,
    ),
    (
        "guaranteed_job",
        "Guaranteed job / no-interview claims",
        [
            r"guaranteed\s*job", r"no\s*interview\s*(needed|required)",
            r"100%\s*selection", r"job\s*confirmed", r"selected\s*instantly",
            r"instant\s*selection",
        ],
        15,
    ),
    (
        "unrealistic_salary",
        "Unrealistic salary or income promise",
        [
            r"earn\s+(rs\.?|₹|inr)?\s*[\d,]+\s*(per\s*day|daily|per\s*week|weekly)",
            r"₹\s*[\d,]{4,}\s*(per\s*day|daily|weekly)", r"huge\s*income",
            r"unlimited\s*earnings", r"easy\s*money",
        ],
        20,
    ),
    (
        "urgency_pressure",
        "Urgency or pressure tactics",
        [
            r"urgent", r"act\s*now", r"hurry", r"limited\s*(time|seats|slots)",
            r"expires?\s*(in|within)", r"final\s*notice", r"only\s*\d+\s*(hour|minute|seat)s?\s*(left)?",
            r"within\s*\d+\s*(minutes|hours)", r"before\s*(it'?s?\s*)?too\s*late",
        ],
        15,
    ),
    (
        "sensitive_info_request",
        "Request for OTP, PIN, password or bank/card details",
        [
            r"\botp\b", r"\bpin\b", r"password", r"cvv", r"card\s*number",
            r"bank\s*(account\s*)?(number|details)", r"aadhaar", r"debit\s*card",
            r"credit\s*card", r"ifsc",
        ],
        25,
    ),
    (
        "telegram_whatsapp_only",
        "Recruitment only through Telegram/WhatsApp (no official channel)",
        [
            r"telegram\s*group", r"whatsapp\s*(only|group)", r"contact\s*us\s*on\s*whatsapp",
            r"join\s*our\s*telegram",
        ],
        10,
    ),
    (
        "fake_interview_claim",
        "Fake or unverifiable interview/selection claim",
        [
            r"you\s*(have\s*)?won", r"you\s*are\s*(the\s*)?winner", r"lucky\s*candidate",
            r"selected\s*without\s*interview",
        ],
        10,
    ),
    (
        "poor_grammar_pressure_words",
        "Excessive urgency punctuation or pressure phrasing",
        [
            r"!{2,}", r"congrat+ulations", r"dear\s*sir/?madam", r"dear\s*winner",
        ],
        5,
    ),
]

URL_PATTERN = re.compile(r"(https?://[^\s]+|www\.[^\s]+|\b[a-zA-Z0-9-]+\.(tk|xyz|info|ml|ga|cf)\b[^\s]*)", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_PATTERN = re.compile(r"(\+?\d{1,3}[-\s]?)?\d{10}\b")

SUSPICIOUS_TLDS = {"tk", "xyz", "info", "ml", "ga", "cf", "top", "buzz"}
FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com"}


def detect_indicators(text):
    """Run each indicator's regex patterns against the text.
    Returns a list of dicts: key, label, weight, matched phrases (deduped)."""
    lowered = text.lower()
    found = []
    for key, label, patterns, weight in INDICATORS:
        matches = []
        for pat in patterns:
            for m in re.finditer(pat, lowered, flags=re.IGNORECASE):
                snippet = text[m.start():m.end()]
                if snippet and snippet not in matches:
                    matches.append(snippet)
        if matches:
            found.append({
                "key": key,
                "label": label,
                "weight": weight,
                "matches": matches[:5],  # cap to keep the UI tidy
            })
    return found


def analyze_links(text):
    """Extract URLs and give a basic, safe (non-visiting) risk read on each."""
    urls = list(dict.fromkeys(m.group(0).rstrip(".,)") for m in URL_PATTERN.finditer(text)))
    results = []
    for url in urls:
        candidate = url if url.startswith("http") else "http://" + url
        parsed = urlparse(candidate)
        domain = parsed.netloc.lower()
        uses_https = url.lower().startswith("https://")
        tld = domain.split(".")[-1] if "." in domain else ""
        suspicious_tld = tld in SUSPICIOUS_TLDS
        has_shortener = any(s in domain for s in ["bit.ly", "tinyurl", "t.co", "cutt.ly", "is.gd"])
        results.append({
            "url": url,
            "domain": domain,
            "https": uses_https,
            "suspicious_tld": suspicious_tld,
            "shortener": has_shortener,
        })
    return results


def analyze_contacts(text):
    """Detect emails and phone numbers, returning only lightweight,
    non-sensitive summary info (not the raw values verbatim beyond domain)."""
    emails = EMAIL_PATTERN.findall(text)
    phone_count = len(re.findall(PHONE_PATTERN, text))

    email_domains = []
    for e in emails:
        domain = e.split("@")[-1].lower()
        email_domains.append({
            "domain": domain,
            "is_free_provider": domain in FREE_EMAIL_DOMAINS,
        })

    return {
        "email_count": len(emails),
        "email_domains": email_domains,
        "phone_count": phone_count,
    }


def highlight_text(text, indicators, urls):
    """Return an HTML-safe version of `text` with suspicious phrases and
    links wrapped in <mark> tags. The base text is escaped first so no
    user-submitted markup can break out of the display area."""
    escaped = html.escape(text)

    phrases_to_highlight = set()
    for ind in indicators:
        for phrase in ind["matches"]:
            phrases_to_highlight.add(html.escape(phrase))
    for url in urls:
        phrases_to_highlight.add(html.escape(url))

    # Longest phrases first so shorter ones don't fragment longer matches.
    for phrase in sorted(phrases_to_highlight, key=len, reverse=True):
        if not phrase.strip():
            continue
        pattern = re.compile(re.escape(phrase), re.IGNORECASE)
        escaped = pattern.sub(lambda m: f'<mark class="hl">{m.group(0)}</mark>', escaped)

    return escaped


def compute_rule_score(indicators):
    """Sum indicator weights, capped at 100."""
    total = sum(ind["weight"] for ind in indicators)
    return min(total, 100)


def combine_scores(rule_score, ml_probabilities):
    """Blend the transparent rule-based score with the ML model's
    confidence in the riskier classes to produce a final 0-100 risk score."""
    ml_risk = 0.0
    if ml_probabilities:
        ml_risk = (
            ml_probabilities.get("scam", 0.0) * 100 * 0.7
            + ml_probabilities.get("suspicious", 0.0) * 100 * 0.4
        )
    final = 0.6 * rule_score + 0.4 * ml_risk
    return round(min(final, 100))


def risk_band(score):
    if score <= 30:
        return "Low Risk", "low"
    elif score <= 60:
        return "Moderate Risk", "moderate"
    else:
        return "High Risk", "high"


def prediction_label_from_score(score, ml_label):
    """Final human-facing prediction: primarily rule/score driven so the
    result stays consistent with what the user sees in the breakdown."""
    if score >= 61:
        return "Potential Scam / High Risk"
    elif score >= 31:
        return "Suspicious"
    else:
        return "Likely Legitimate"


def generate_safety_tips(indicators):
    tip_map = {
        "payment_request": "Never pay a recruitment, registration, or security-deposit fee to get a job.",
        "guaranteed_job": "Be wary of any offer that guarantees selection without an interview or assessment.",
        "unrealistic_salary": "Treat unusually high pay for simple, unskilled work as a warning sign.",
        "urgency_pressure": "Genuine employers do not pressure you to decide or pay within minutes or hours.",
        "sensitive_info_request": "Never share OTPs, passwords, PINs, or full bank/card details with a recruiter.",
        "telegram_whatsapp_only": "Be cautious of recruitment conducted only over WhatsApp/Telegram with no official email.",
        "fake_interview_claim": "You cannot 'win' a job you never applied for — verify any such claim independently.",
        "poor_grammar_pressure_words": "Excessive urgency and exclamation marks are common manipulation tactics.",
    }
    tips = [tip_map[i["key"]] for i in indicators if i["key"] in tip_map]
    tips.append("Verify the company through its official website and contact them independently.")
    tips.append("Check whether the recruiter's email uses the company's official domain.")
    # Deduplicate while preserving order
    seen = set()
    unique_tips = []
    for t in tips:
        if t not in seen:
            unique_tips.append(t)
            seen.add(t)
    return unique_tips


def get_history():
    return session.get("analysis_history", [])


def push_history(entry):
    history = get_history()
    history.insert(0, entry)
    session["analysis_history"] = history[:MAX_HISTORY_ITEMS]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    metrics = MODEL_BUNDLE.get("metrics")
    return render_template(
        "index.html",
        metrics=metrics,
        used_fallback_data=MODEL_BUNDLE.get("used_fallback_data"),
        dataset_size=MODEL_BUNDLE.get("dataset_size"),
        history=get_history(),
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(silent=True) or {}
        text = (data.get("text") or "").strip()

        if not text:
            return jsonify({"error": "Please paste a job offer message before analyzing."}), 400

        if len(text) < MIN_MESSAGE_LENGTH:
            return jsonify({"error": "This message is too short to analyze reliably. Please paste more of the conversation."}), 400

        # --- Rule-based layer ---
        indicators = detect_indicators(text)
        rule_score = compute_rule_score(indicators)
        links = analyze_links(text)
        contacts = analyze_contacts(text)
        highlighted_html = highlight_text(text, indicators, [l["url"] for l in links])

        if any(l["suspicious_tld"] or l["shortener"] for l in links):
            # small bump for genuinely risky-looking links, part of the transparent rule layer
            rule_score = min(rule_score + 10, 100)

        # --- ML layer ---
        vectorizer = MODEL_BUNDLE["vectorizer"]
        clf = MODEL_BUNDLE["classifier"]
        vec = vectorizer.transform([text])
        ml_pred = clf.predict(vec)[0]

        ml_probabilities = {}
        confidence = None
        try:
            proba = clf.predict_proba(vec)[0]
            classes = clf.classes_
            ml_probabilities = {cls: float(p) for cls, p in zip(classes, proba)}
            confidence = round(max(proba) * 100)
        except Exception:
            confidence = None

        final_score = combine_scores(rule_score, ml_probabilities)
        band_label, band_key = risk_band(final_score)
        prediction = prediction_label_from_score(final_score, ml_pred)

        safety_tips = generate_safety_tips(indicators)

        result = {
            "prediction": prediction,
            "ml_raw_label": ml_pred,
            "risk_score": final_score,
            "risk_band": band_label,
            "risk_band_key": band_key,
            "confidence": confidence,
            "ml_probabilities": {k: round(v * 100) for k, v in ml_probabilities.items()},
            "rule_score": rule_score,
            "indicators": indicators,
            "links": links,
            "contacts": contacts,
            "highlighted_html": highlighted_html,
            "safety_tips": safety_tips,
            "recommended_action": (
                "Do not send money or sensitive information until the employer is independently verified."
                if final_score > 30 else
                "No major red flags detected, but always verify any employer independently before sharing personal details."
            ),
        }

        push_history({
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "prediction": prediction,
            "risk_score": final_score,
            "risk_band_key": band_key,
        })
        result["history"] = get_history()

        return jsonify(result), 200

    except Exception as exc:  # pragma: no cover - defensive catch-all
        app.logger.exception("Error during analysis")
        return jsonify({"error": "Something went wrong while analyzing the message. Please try again."}), 500


@app.route("/model-info")
def model_info():
    """Small JSON endpoint exposing model performance for the 'How AI Works' section."""
    return jsonify({
        "metrics": MODEL_BUNDLE.get("metrics"),
        "used_fallback_data": MODEL_BUNDLE.get("used_fallback_data"),
        "dataset_size": MODEL_BUNDLE.get("dataset_size"),
        "labels": MODEL_BUNDLE.get("labels"),
    })


if __name__ == "__main__":
   app.run(debug=True, use_reloader=False, host="127.0.0.1", port=5000)