def analyze_authentication(headers):
    text = " ".join(str(v).lower() for v in headers.values())
    checks = {}
    checks["spf"] = "pass" if "spf=pass" in text or "received-spf: pass" in text else (
        "fail" if "spf=fail" in text else "not available")
    checks["dkim"] = "pass" if "dkim=pass" in text else (
        "fail" if "dkim=fail" in text else "not available")
    checks["dmarc"] = "pass" if "dmarc=pass" in text else (
        "fail" if "dmarc=fail" in text else "not available")
    score = sum(1 for v in checks.values() if v == "pass")
    fails = sum(1 for v in checks.values() if v == "fail")
    return {
        "checks": checks,
        "passes": score,
        "fails": fails,
        "note": "Results are read from supplied email authentication headers; they are not independently verified by an SMTP receiver.",
    }
