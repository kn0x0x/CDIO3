"""Quick smoke test for the CDIO Threat Intelligence backend.

Run while backend is active:
    python scripts/demo_test.py
"""
from __future__ import annotations

import json
import sys
from urllib.request import Request, urlopen

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"


def get(path: str):
    with urlopen(f"{BASE_URL}{path}", timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))
    print(f"GET {path}: {payload['message']}")
    return payload["data"]


def post(path: str, body: dict | None = None):
    data = json.dumps(body or {}).encode("utf-8")
    req = Request(f"{BASE_URL}{path}", data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    print(f"POST {path}: {payload['message']}")
    return payload["data"]


if __name__ == "__main__":
    health = get("/health")
    dashboard = get("/api/v1/dashboard")
    alerts = get("/api/v1/alerts?limit=3")
    enrich = post("/api/v1/pipeline/enrich/50.16.16.211")
    ml = post("/api/v1/ml/predict", {"indicator_value": "CVE-2024-3400", "tags": ["cve", "kev", "exploit"]})
    collector = get("/api/v1/collector/status")
    print("\nSummary")
    print("-------")
    print(f"Backend status      : {health['status']}")
    print(f"Total IoC/alerts    : {dashboard['metrics']['total_threats']}")
    print(f"Recent sample       : {alerts[0]['indicator_value']} ({alerts[0]['severity']})")
    print(f"50.16.16.211 enrich : {enrich['enrichment']['asn']} / risk={enrich['risk']['risk_score']}")
    print(f"ML tactic CVE       : {ml['ml_tactic']} ({ml['ml_confidence']}) / rule={ml['rule_based_mitre']['mitre_tactic']}")
    print(f"Collector running   : {collector['running']} / feeds={len(collector['collectors'])}")
