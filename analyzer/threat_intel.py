import socket
import ipaddress

from .url_analyzer import analyze_urls

socket.setdefaulttimeout(2.0)  # keep reverse-DNS lookups from hanging a request


def geo_ip(ip):
    try:
        x = ipaddress.ip_address(ip)
    except Exception:
        return {"ip": ip, "type": "invalid"}
    if x.is_private or x.is_loopback or x.is_link_local:
        return {"ip": ip, "type": "private/local"}
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        host = None
    return {"ip": ip, "type": "public", "reverse_dns": host}


def enrich_iocs(urls, ips):
    return {
        "urls": analyze_urls(urls),
        "ips": [geo_ip(x) for x in ips],
        "sources": ["Local URL heuristics", "DNS reverse lookup when available"],
        "api_status": "Optional external threat-intelligence APIs can be added via environment variables.",
    }
