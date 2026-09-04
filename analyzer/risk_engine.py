def calculate_risk(r):
    score = 0
    reasons = []

    indicators = r.get("indicators", [])
    n = len(indicators)
    if n:
        score += min(30, n * 5)
        reasons.append(f"{n} suspicious content/header indicator(s)")

    # A few indicator types are strong signals on their own; weight them extra.
    if any("attachment" in i.lower() for i in indicators):
        score += 10
        reasons.append("Suspicious executable-type attachment present")
    if any("domain mismatch" in i.lower() or "display name references" in i.lower() for i in indicators):
        score += 10
        reasons.append("Sender identity looks spoofed or impersonated")

    urls = r.get("threat_intelligence", {}).get("urls", [])
    sus = sum(1 for x in urls if x["suspicious"])
    if sus:
        score += min(35, sus * 10)
        reasons.append(f"{sus} suspicious URL(s)")

    if r.get("ips"):
        score += min(10, len(r["ips"]) * 2)
        reasons.append(f"{len(r['ips'])} IP address(es) found")

    p = float(r.get("ml", {}).get("probability", 0))
    score += round(p * 25)
    if p >= 0.55:
        reasons.append("ML baseline classified content as phishing")

    auth = r.get("authentication", {}).get("checks", {})
    fails = sum(1 for v in auth.values() if v == "fail")
    if fails:
        score += fails * 8
        reasons.append(f"{fails} authentication check(s) failed")

    score = min(100, score)
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    return {"score": score, "level": level, "reasons": reasons}
