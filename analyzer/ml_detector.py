import re

# Explainable statistical baseline trained from a small embedded seed corpus.
# It is intentionally self-contained so deployment needs no model download.
PHISH = [
    "verify your account", "reset your password", "urgent action required", "click here to login",
    "account suspended", "security alert", "payment required", "wire transfer", "gift card",
    "confirm your account", "invoice overdue", "verify immediately", "unusual activity detected",
    "confirm your identity", "your account will be closed", "final notice", "act now",
    "one time password", "avoid suspension", "click the link below",
]
SAFE = [
    "meeting agenda", "project update", "lunch", "class schedule", "thank you for your message",
    "weekly report", "assignment", "receipt for your purchase", "newsletter", "appointment reminder",
    "unsubscribe", "team standup", "pull request", "invoice attached for your records",
]
URGENCY_WORDS = re.compile(r"\b(immediately|urgent|now|24 hours|expire[sd]?|final notice|act now|asap)\b")
SENSITIVE_WORDS = re.compile(r"\b(password|otp|verification code|bank|ssn|social security|routing number|card number)\b")
MONEY_WORDS = re.compile(r"\b(wire transfer|bitcoin|crypto|gift card|western union|invoice)\b")


def tokenize(s):
    return set(re.findall(r"[a-z0-9@._-]+", s.lower()))


def predict_email(subject, body):
    text = (subject + " " + body).lower()
    score = 0.03
    hits = [p for p in PHISH if p in text]
    safe = [p for p in SAFE if p in text]

    score += min(0.62, len(hits) * 0.08)
    score -= min(0.15, len(safe) * 0.04)

    urgency_hits = len(URGENCY_WORDS.findall(text))
    score += min(0.12, urgency_hits * 0.04)

    if re.search(r"https?://", text):
        score += 0.05
    if SENSITIVE_WORDS.search(text):
        score += 0.10
    if MONEY_WORDS.search(text):
        score += 0.08
    # ALL-CAPS subject lines / exclamation spam are mild signals.
    if subject and subject.isupper() and len(subject) > 6:
        score += 0.04
    if subject.count("!") >= 2:
        score += 0.03

    score = max(0.01, min(0.99, score))
    label = "PHISHING" if score >= 0.55 else ("SUSPICIOUS" if score >= 0.30 else "LIKELY SAFE")
    return {
        "label": label,
        "probability": round(score, 3),
        "model": "Explainable NLP baseline",
        "matched_phishing_patterns": hits,
        "matched_safe_patterns": safe,
        "urgency_signals": urgency_hits,
        "note": "Self-contained baseline; replace/augment with a trained production classifier for deployment at scale.",
    }
