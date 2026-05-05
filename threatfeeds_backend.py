"""Threat Intelligence CDIO Backend.

FastAPI + SQLite backend for the CDIO project:
- Threat feed management and collector scheduler
- IoC normalization, deduplication, enrichment, risk scoring
- MITRE ATT&CK mapping
- scikit-learn ML model for tactic suggestion
- Dashboard/analytics/map endpoints for React frontend
- Optional Telegram notifications

Run locally:
    pip install -r requirements.txt
    python threatfeeds_backend.py
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import sqlite3
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Literal
from uuid import uuid4

import httpx
from dotenv import load_dotenv
from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

try:  # scikit-learn is used for the ML part; backend has a heuristic fallback.
    import joblib
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline

    SKLEARN_AVAILABLE = True
except Exception:  # pragma: no cover - fallback path for minimal environments
    joblib = None
    np = None
    TfidfVectorizer = MultinomialNB = Pipeline = None
    accuracy_score = classification_report = confusion_matrix = f1_score = train_test_split = None
    SKLEARN_AVAILABLE = False

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
APP_NAME = "ThreatShield CDIO Threat Intelligence API"
APP_VERSION = "2.0.0"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
DB_PATH = Path(os.getenv("DATABASE_PATH", BASE_DIR / "threatfeeds.db"))
DEBUG_MODE = os.getenv("DEBUG", "1") == "1"
COLLECTOR_ENABLED = os.getenv("COLLECTOR_ENABLED", "1") == "1"
COLLECTOR_INTERVAL_MINUTES = int(os.getenv("COLLECTOR_INTERVAL_MINUTES", "30"))
SEED_ALERT_COUNT = int(os.getenv("SEED_ALERT_COUNT", "916"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
REQUEST_TIMEOUT = float(os.getenv("FEED_REQUEST_TIMEOUT", "3"))
REMOTE_FEEDS_ENABLED = os.getenv("REMOTE_FEEDS_ENABLED", "0") == "1"
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "80"))

DATA_DIR.mkdir(exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("threatshield")

_db_lock = threading.RLock()
_ml_lock = threading.RLock()
_ml_model: Any | None = None
_ml_metrics: dict[str, Any] = {}
_scheduler: "CollectorScheduler | None" = None

SEVERITIES = ("critical", "high", "medium", "low")
INDICATOR_TYPES = ("ip", "domain", "url", "hash", "email", "cve", "file")
ALERT_STATUSES = ("active", "investigating", "mitigated")

COUNTRY_GEO = [
    ("US", "United States", "Virginia", 37.4316, -78.6569, "AS14618 Amazon.com"),
    ("VN", "Vietnam", "Ho Chi Minh City", 10.8231, 106.6297, "AS7552 Viettel"),
    ("DE", "Germany", "Frankfurt", 50.1109, 8.6821, "AS3320 Deutsche Telekom"),
    ("GB", "United Kingdom", "London", 51.5074, -0.1278, "AS15169 Google"),
    ("SG", "Singapore", "Singapore", 1.3521, 103.8198, "AS16509 AWS"),
    ("JP", "Japan", "Tokyo", 35.6762, 139.6503, "AS2516 KDDI"),
    ("KR", "South Korea", "Seoul", 37.5665, 126.9780, "AS9318 SK Broadband"),
    ("RU", "Russia", "Moscow", 55.7558, 37.6173, "AS12389 Rostelecom"),
    ("BR", "Brazil", "Sao Paulo", -23.5505, -46.6333, "AS28573 Claro"),
    ("AU", "Australia", "Sydney", -33.8688, 151.2093, "AS1221 Telstra"),
    ("IN", "India", "Mumbai", 19.0760, 72.8777, "AS4755 TATA"),
    ("NL", "Netherlands", "Amsterdam", 52.3676, 4.9041, "AS60781 LeaseWeb"),
    ("FR", "France", "Paris", 48.8566, 2.3522, "AS3215 Orange"),
    ("CA", "Canada", "Toronto", 43.6532, -79.3832, "AS577 Bell Canada"),
    ("CN", "China", "Beijing", 39.9042, 116.4074, "AS4134 China Telecom"),
]

SOURCE_TRUST = {
    "CISA KEV": 98,
    "Abuse.ch URLhaus": 94,
    "MalwareBazaar": 92,
    "Feodo Tracker": 88,
    "AlienVault OTX": 82,
    "PhishTank": 78,
    "Community CSV": 66,
}

MITRE_RULES = [
    {
        "keywords": ["phishing", "credential", "email", "login", "microsoft", "o365"],
        "indicator_types": ["domain", "url", "email"],
        "tactic": "Initial Access",
        "technique": "T1566 - Phishing",
        "attack_vector": "Email",
    },
    {
        "keywords": ["cve", "kev", "exploit", "vulnerability", "command injection", "rce", "vpn"],
        "indicator_types": ["cve"],
        "tactic": "Initial Access",
        "technique": "T1190 - Exploit Public-Facing Application",
        "attack_vector": "Web",
    },
    {
        "keywords": ["ransomware", "lockbit", "payload", "trojan", "rat", "keylogger", "malware", "hash", "exe"],
        "indicator_types": ["hash", "file"],
        "tactic": "Execution",
        "technique": "T1204.002 - Malicious File",
        "attack_vector": "Endpoint",
    },
    {
        "keywords": ["c2", "command", "botnet", "feodo", "emotet", "trickbot", "dridex", "dns", "beacon"],
        "indicator_types": ["ip", "domain"],
        "tactic": "Command and Control",
        "technique": "T1071 - Application Layer Protocol",
        "attack_vector": "Network",
    },
    {
        "keywords": ["ddos", "botnet", "flood"],
        "indicator_types": ["ip"],
        "tactic": "Impact",
        "technique": "T1498 - Network Denial of Service",
        "attack_vector": "Network",
    },
    {
        "keywords": ["scan", "recon", "port", "probing"],
        "indicator_types": ["ip"],
        "tactic": "Reconnaissance",
        "technique": "T1595 - Active Scanning",
        "attack_vector": "Network",
    },
    {
        "keywords": ["brute", "password", "login", "credential stuffing"],
        "indicator_types": ["ip", "domain"],
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "attack_vector": "Identity",
    },
    {
        "keywords": ["exfil", "tunnel", "dns tunneling", "dropbox", "mega"],
        "indicator_types": ["domain", "url", "ip"],
        "tactic": "Exfiltration",
        "technique": "T1567 - Exfiltration Over Web Service",
        "attack_vector": "Cloud",
    },
]

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def dict_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def json_loads(value: str | None, default: Any) -> Any:
    if value is None or value == "":
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def init_db() -> None:
    with _db_lock, get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS feeds (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source_url TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL DEFAULT 'API',
                description TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                last_fetched_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                feed_id TEXT NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                description TEXT,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                normalized_value TEXT NOT NULL UNIQUE,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.5,
                risk_score INTEGER NOT NULL DEFAULT 50,
                status TEXT NOT NULL DEFAULT 'active',
                country_code TEXT,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                asn TEXT,
                reputation INTEGER NOT NULL DEFAULT 50,
                mitre_tactic TEXT,
                mitre_technique TEXT,
                attack_vector TEXT,
                ml_tactic TEXT,
                ml_confidence REAL DEFAULT 0,
                tags TEXT NOT NULL DEFAULT '[]',
                published_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS collection_runs (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                success INTEGER NOT NULL DEFAULT 0,
                new_count INTEGER NOT NULL DEFAULT 0,
                duplicate_count INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                details TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS ml_runs (
                id TEXT PRIMARY KEY,
                trained_at TEXT NOT NULL,
                train_size INTEGER NOT NULL,
                test_size INTEGER NOT NULL,
                accuracy REAL NOT NULL,
                macro_f1 REAL NOT NULL,
                labels TEXT NOT NULL,
                confusion_matrix TEXT NOT NULL,
                classification_report TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(indicator_type);
            CREATE INDEX IF NOT EXISTS idx_alerts_feed ON alerts(feed_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_published ON alerts(published_at DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_country ON alerts(country);
            CREATE INDEX IF NOT EXISTS idx_alerts_mitre ON alerts(mitre_tactic);
            """
        )
        conn.commit()

# ---------------------------------------------------------------------------
# IoC analysis helpers
# ---------------------------------------------------------------------------
def stable_int(text: str, modulo: int = 10_000) -> int:
    digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
    return int(digest[:12], 16) % modulo


def normalize_indicator(value: str) -> str:
    value = value.strip()
    value = value.replace("hxxp://", "http://").replace("hxxps://", "https://")
    value = value.replace("[.]", ".").replace("(.)", ".")
    value = value.replace(" ", "")
    if value.upper().startswith("CVE-"):
        return value.upper()
    return value.lower()


def infer_indicator_type(value: str) -> str:
    normalized = normalize_indicator(value)
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", normalized.upper()):
        return "cve"
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", normalized):
        return "hash"
    if re.match(r"https?://", normalized):
        return "url"
    if "@" in normalized and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
        return "email"
    try:
        ipaddress.ip_address(normalized)
        return "ip"
    except Exception:
        pass
    if re.search(r"\.(exe|dll|scr|bat|ps1|js|vbs|docm|xlsm)$", normalized):
        return "file"
    return "domain"


def mitre_mapping(indicator_type: str, title: str, description: str | None, tags: Iterable[str], value: str = "") -> dict[str, str]:
    text = " ".join([indicator_type, title or "", description or "", value or "", " ".join(tags)]).lower()
    best: dict[str, str] | None = None
    best_score = -1
    for rule in MITRE_RULES:
        score = 0
        if indicator_type in rule["indicator_types"]:
            score += 3
        score += sum(2 for kw in rule["keywords"] if kw in text)
        if score > best_score:
            best_score = score
            best = rule
    if not best or best_score <= 0:
        return {
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1046 - Network Service Discovery",
            "attack_vector": "Network",
        }
    return {
        "mitre_tactic": best["tactic"],
        "mitre_technique": best["technique"],
        "attack_vector": best["attack_vector"],
    }


def enrich_indicator(indicator_value: str, indicator_type: str) -> dict[str, Any]:
    normalized = normalize_indicator(indicator_value)
    if normalized == "50.16.16.211":
        return {
            "country_code": "US",
            "country": "United States",
            "city": "Ashburn",
            "latitude": 39.0438,
            "longitude": -77.4874,
            "asn": "AS14618 Amazon.com AWS EC2 us-east-1",
            "reputation": 87,
        }

    idx = stable_int(normalized, len(COUNTRY_GEO))
    country_code, country, city, lat, lon, asn = COUNTRY_GEO[idx]
    jitter_lat = (stable_int(normalized + "lat", 1000) / 1000 - 0.5) * 2.5
    jitter_lon = (stable_int(normalized + "lon", 1000) / 1000 - 0.5) * 2.5
    base_rep = 35 + stable_int(normalized + "rep", 60)
    if indicator_type in {"cve", "hash", "file"}:
        base_rep += 8
    if indicator_type == "ip":
        try:
            ip = ipaddress.ip_address(normalized)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                base_rep = min(base_rep, 40)
        except Exception:
            pass
    return {
        "country_code": country_code,
        "country": country,
        "city": city,
        "latitude": round(lat + jitter_lat, 4),
        "longitude": round(lon + jitter_lon, 4),
        "asn": asn,
        "reputation": min(100, max(1, int(base_rep))),
    }


def score_indicator(
    indicator_value: str,
    indicator_type: str,
    feed_name: str,
    tags: Iterable[str],
    mitre_tactic: str,
    reputation: int,
) -> dict[str, Any]:
    normalized = normalize_indicator(indicator_value)
    tag_text = " ".join(tags).lower()
    source_trust = SOURCE_TRUST.get(feed_name, 72)
    frequency = 35 + stable_int(normalized + "freq", 65)
    cve_score = 0
    if indicator_type == "cve":
        cve_score = 80 + stable_int(normalized + "cvss", 20)
    elif any(k in tag_text for k in ("exploit", "kev", "ransomware", "lockbit")):
        cve_score = 55
    attack_score = 88 if mitre_tactic in {"Initial Access", "Command and Control", "Impact", "Exfiltration"} else 65
    risk = int(round(reputation * 0.35 + cve_score * 0.20 + frequency * 0.15 + source_trust * 0.15 + attack_score * 0.15))
    if any(k in tag_text for k in ("critical", "kev", "ransomware", "lockbit")):
        risk = min(100, risk + 8)
    if any(k in tag_text for k in ("low-confidence", "pup", "noise")):
        risk = max(1, risk - 20)

    if risk >= 85:
        severity = "critical"
    elif risk >= 70:
        severity = "high"
    elif risk >= 45:
        severity = "medium"
    else:
        severity = "low"
    confidence = min(1.0, max(0.2, round((risk / 100) * 0.85 + source_trust / 100 * 0.15, 2)))
    return {"risk_score": risk, "severity": severity, "confidence": confidence}


def alert_status_for(severity: str, risk_score: int) -> str:
    if severity == "critical" or risk_score >= 82:
        return "active"
    if severity == "high":
        return "investigating"
    return "mitigated" if risk_score < 50 else "investigating"


def ml_text_from_alert(alert: dict[str, Any]) -> str:
    tags = alert.get("tags")
    if isinstance(tags, str):
        tags = json_loads(tags, [])
    tags_text = " ".join(tags or [])
    parts = [
        str(alert.get("indicator_type", "")),
        str(alert.get("indicator_value", "")),
        str(alert.get("title", "")),
        str(alert.get("description", "")),
        tags_text,
        str(alert.get("attack_vector", "")),
    ]
    return " ".join(parts)


def heuristic_predict_tactic(alert: dict[str, Any]) -> tuple[str, float]:
    mapping = mitre_mapping(
        alert.get("indicator_type", "domain"),
        alert.get("title", ""),
        alert.get("description"),
        json_loads(alert.get("tags"), []) if isinstance(alert.get("tags"), str) else alert.get("tags", []),
        alert.get("indicator_value", ""),
    )
    confidence = min(0.95, max(0.55, (alert.get("risk_score") or 60) / 100))
    return mapping["mitre_tactic"], round(confidence, 2)

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class APIResponse(BaseModel):
    success: bool = True
    message: str = "ok"
    data: Any = None
    meta: dict[str, Any] = Field(default_factory=dict)


class FeedCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    source_url: str | None = Field(default=None, min_length=5, max_length=2048)
    url: str | None = Field(default=None, min_length=5, max_length=2048)
    source: str = "API"
    description: str | None = None
    enabled: bool = True

    @field_validator("source_url", "url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        if value and not value.startswith(("http://", "https://", "file://")):
            raise ValueError("URL must start with http://, https:// or file://")
        return value

    @property
    def resolved_url(self) -> str:
        value = self.source_url or self.url
        if not value:
            raise ValueError("source_url/url is required")
        return value


class FeedUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    source_url: str | None = Field(default=None, min_length=5, max_length=2048)
    url: str | None = Field(default=None, min_length=5, max_length=2048)
    source: str | None = None
    description: str | None = None
    status: Literal["active", "inactive"] | None = None
    enabled: bool | None = None


class AlertCreate(BaseModel):
    feed_id: str
    title: str = Field(min_length=3, max_length=512)
    description: str | None = None
    indicator_type: Literal["ip", "domain", "url", "hash", "email", "cve", "file"] | None = None
    indicator_value: str = Field(min_length=1, max_length=2048)
    severity: Literal["critical", "high", "medium", "low"] | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    risk_score: int | None = Field(default=None, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)


class AlertUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=512)
    description: str | None = None
    severity: Literal["critical", "high", "medium", "low"] | None = None
    status: Literal["active", "investigating", "mitigated"] | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    risk_score: int | None = Field(default=None, ge=0, le=100)
    tags: list[str] | None = None


class MLPredictRequest(BaseModel):
    indicator_value: str
    indicator_type: Literal["ip", "domain", "url", "hash", "email", "cve", "file"] | None = None
    title: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    feed_name: str = "Manual"


class TelegramTestRequest(BaseModel):
    message: str | None = None

# ---------------------------------------------------------------------------
# Serialization and SQL helpers
# ---------------------------------------------------------------------------
def api_ok(data: Any = None, message: str = "ok", meta: dict[str, Any] | None = None) -> APIResponse:
    return APIResponse(success=True, message=message, data=data, meta=meta or {})


def feed_out(row: sqlite3.Row | dict[str, Any], alert_count: int | None = None) -> dict[str, Any]:
    data = dict(row)
    enabled = data.get("status") == "active"
    if alert_count is None:
        with _db_lock, get_conn() as conn:
            alert_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE feed_id=?", (data["id"],)).fetchone()[0]
    return {
        **data,
        "url": data.get("source_url"),
        "enabled": enabled,
        "last_updated": data.get("last_fetched_at"),
        "alert_count": int(alert_count or 0),
    }


def alert_out(row: sqlite3.Row | dict[str, Any], feed_name: str | None = None) -> dict[str, Any]:
    data = dict(row)
    tags = json_loads(data.get("tags"), [])
    if feed_name is None:
        with _db_lock, get_conn() as conn:
            feed = conn.execute("SELECT name FROM feeds WHERE id=?", (data["feed_id"],)).fetchone()
            feed_name = feed[0] if feed else "Unknown"
    status_value = data.get("status") or alert_status_for(data.get("severity", "medium"), data.get("risk_score", 50))
    return {
        **data,
        "tags": tags,
        "feed_name": feed_name,
        "source": feed_name,
        "type": data.get("indicator_type"),
        "indicator": data.get("indicator_value"),
        "status": status_value,
        "lat": data.get("latitude"),
        "lng": data.get("longitude"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
    }


def get_feed_by_id(conn: sqlite3.Connection, feed_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM feeds WHERE id=?", (feed_id,)).fetchone()


def get_feed_by_name(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM feeds WHERE name=?", (name,)).fetchone()


def insert_feed(conn: sqlite3.Connection, name: str, source_url: str, source: str = "API", description: str | None = None, status_value: str = "active") -> str:
    existing = conn.execute("SELECT id FROM feeds WHERE source_url=?", (source_url,)).fetchone()
    if existing:
        return existing["id"]
    fid = str(uuid4())
    ts = utcnow()
    conn.execute(
        """
        INSERT INTO feeds(id,name,source_url,source,description,status,last_fetched_at,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (fid, name, source_url, source, description, status_value, None, ts, ts),
    )
    return fid


def prepare_alert_record(
    *,
    feed_id: str,
    feed_name: str,
    indicator_value: str,
    title: str | None = None,
    description: str | None = None,
    indicator_type: str | None = None,
    tags: list[str] | None = None,
    published_at: str | None = None,
    severity: str | None = None,
    confidence: float | None = None,
    risk_score: int | None = None,
) -> dict[str, Any]:
    normalized = normalize_indicator(indicator_value)
    detected_type = indicator_type or infer_indicator_type(normalized)
    tags = tags or []
    default_title = title or f"{detected_type.upper()} indicator from {feed_name}"
    default_desc = description or f"Normalized IoC collected from {feed_name}: {normalized}"
    enrichment = enrich_indicator(normalized, detected_type)
    mitre = mitre_mapping(detected_type, default_title, default_desc, tags, normalized)
    score = score_indicator(normalized, detected_type, feed_name, tags, mitre["mitre_tactic"], enrichment["reputation"])
    final_risk = int(risk_score if risk_score is not None else score["risk_score"])
    final_severity = severity or score["severity"]
    final_confidence = float(confidence if confidence is not None else score["confidence"])
    heuristic_tactic, heuristic_conf = heuristic_predict_tactic({
        "indicator_type": detected_type,
        "indicator_value": normalized,
        "title": default_title,
        "description": default_desc,
        "tags": tags,
        "risk_score": final_risk,
    })
    return {
        "id": str(uuid4()),
        "feed_id": feed_id,
        "title": default_title,
        "description": default_desc,
        "indicator_type": detected_type,
        "indicator_value": normalized,
        "normalized_value": normalized,
        "severity": final_severity,
        "confidence": final_confidence,
        "risk_score": final_risk,
        "status": alert_status_for(final_severity, final_risk),
        "country_code": enrichment["country_code"],
        "country": enrichment["country"],
        "city": enrichment["city"],
        "latitude": enrichment["latitude"],
        "longitude": enrichment["longitude"],
        "asn": enrichment["asn"],
        "reputation": enrichment["reputation"],
        "mitre_tactic": mitre["mitre_tactic"],
        "mitre_technique": mitre["mitre_technique"],
        "attack_vector": mitre["attack_vector"],
        "ml_tactic": heuristic_tactic,
        "ml_confidence": heuristic_conf,
        "tags": json_dumps(sorted(set(tags))),
        "published_at": published_at or utcnow(),
        "created_at": utcnow(),
        "updated_at": utcnow(),
    }


def insert_alert_record(conn: sqlite3.Connection, record: dict[str, Any]) -> tuple[bool, str]:
    fields = [
        "id", "feed_id", "title", "description", "indicator_type", "indicator_value", "normalized_value",
        "severity", "confidence", "risk_score", "status", "country_code", "country", "city", "latitude", "longitude",
        "asn", "reputation", "mitre_tactic", "mitre_technique", "attack_vector", "ml_tactic", "ml_confidence",
        "tags", "published_at", "created_at", "updated_at",
    ]
    placeholders = ",".join(["?"] * len(fields))
    try:
        conn.execute(
            f"INSERT INTO alerts({','.join(fields)}) VALUES({placeholders})",
            tuple(record[f] for f in fields),
        )
        return True, record["id"]
    except sqlite3.IntegrityError:
        return False, record["normalized_value"]

# ---------------------------------------------------------------------------
# Demo data seed
# ---------------------------------------------------------------------------
def default_feeds() -> list[dict[str, str]]:
    return [
        {
            "name": "AlienVault OTX",
            "source_url": "https://otx.alienvault.com/api/v1/indicators/export",
            "source": "API",
            "description": "Open Threat Exchange community IoC feed",
        },
        {
            "name": "Abuse.ch URLhaus",
            "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "source": "CSV",
            "description": "Malicious URLs used for malware distribution",
        },
        {
            "name": "Feodo Tracker",
            "source_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            "source": "JSON",
            "description": "Feodo/Dridex/Emotet/TrickBot C2 servers",
        },
        {
            "name": "PhishTank",
            "source_url": "https://data.phishtank.com/data/online-valid.json",
            "source": "JSON",
            "description": "Community verified phishing URLs",
        },
        {
            "name": "CISA KEV",
            "source_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "source": "JSON",
            "description": "Known Exploited Vulnerabilities catalog",
        },
        {
            "name": "MalwareBazaar",
            "source_url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
            "source": "TXT",
            "description": "Recent malware sample hashes",
        },
        {
            "name": "Community CSV",
            "source_url": "file://data/local-community-iocs.csv",
            "source": "CSV",
            "description": "Local demo feed for offline testing",
        },
    ]


def seed_templates() -> list[dict[str, Any]]:
    return [
        {
            "indicator_type": "ip",
            "title": "C2 server observed in botnet campaign",
            "description": "Command and control endpoint used by Feodo-like malware family",
            "tags": ["c2", "botnet", "feodo", "network"],
        },
        {
            "indicator_type": "url",
            "title": "URLhaus malware delivery URL",
            "description": "URL distributing executable payload through compromised host",
            "tags": ["malware", "payload", "urlhaus", "exe"],
        },
        {
            "indicator_type": "domain",
            "title": "Credential phishing domain",
            "description": "Lookalike domain used to collect Microsoft 365 credentials",
            "tags": ["phishing", "credential", "microsoft", "login"],
        },
        {
            "indicator_type": "hash",
            "title": "MalwareBazaar ransomware sample",
            "description": "SHA-256 hash associated with LockBit/RAT payload",
            "tags": ["ransomware", "lockbit", "hash", "critical"],
        },
        {
            "indicator_type": "cve",
            "title": "CISA KEV exploited vulnerability",
            "description": "Known exploited vulnerability observed in active campaigns",
            "tags": ["cve", "kev", "exploit", "rce"],
        },
        {
            "indicator_type": "file",
            "title": "Suspicious attachment filename",
            "description": "Executable attachment delivered in email campaign",
            "tags": ["malware", "email", "trojan", "file"],
        },
        {
            "indicator_type": "email",
            "title": "Phishing sender address",
            "description": "Sender address used in credential harvesting emails",
            "tags": ["phishing", "email", "credential"],
        },
        {
            "indicator_type": "ip",
            "title": "Reconnaissance and port scanning host",
            "description": "Host scanning exposed services and VPN portals",
            "tags": ["scan", "recon", "port", "probing"],
        },
        {
            "indicator_type": "domain",
            "title": "DNS tunneling indicator",
            "description": "Domain pattern used for potential exfiltration via DNS",
            "tags": ["exfil", "dns-tunneling", "suspicious"],
        },
        {
            "indicator_type": "ip",
            "title": "DDoS botnet node",
            "description": "IP observed in volumetric DDoS traffic",
            "tags": ["ddos", "botnet", "impact"],
        },
    ]


def make_indicator_value(indicator_type: str, i: int) -> str:
    if i == 0:
        return "50.16.16.211"
    if indicator_type == "ip":
        a = 20 + (i * 17) % 200
        b = (i * 29) % 250
        c = (i * 37) % 250
        d = 2 + (i * 43) % 250
        return f"{a}.{b}.{c}.{d}"
    if indicator_type == "url":
        tlds = ["ru", "cn", "top", "xyz", "site", "pw"]
        return f"http://malware-{i}.badcdn-{i % 31}.{tlds[i % len(tlds)]}/payload_{i}.exe"
    if indicator_type == "domain":
        labels = ["secure-update", "o365-login", "cdn-check", "exfil-tunnel", "vpn-portal", "bank-auth"]
        return f"{labels[i % len(labels)]}-{i}.example-threat.net"
    if indicator_type == "hash":
        return hashlib.sha256(f"malware-sample-{i}".encode()).hexdigest()
    if indicator_type == "cve":
        year = 2021 + (i % 5)
        return f"CVE-{year}-{1000 + i:04d}"
    if indicator_type == "file":
        names = ["invoice", "update", "vpn_patch", "salary", "document", "scanner"]
        return f"{names[i % len(names)]}_{i}.exe"
    if indicator_type == "email":
        return f"support-{i}@login-alerts-{i % 17}.example"
    return f"indicator-{i}.example"


def seed_demo_data(force: bool = False) -> None:
    with _db_lock, get_conn() as conn:
        existing = conn.execute("SELECT COUNT(*) FROM feeds").fetchone()[0]
        if existing and not force:
            logger.info("Database already seeded (%d feeds).", existing)
            return
        if force:
            conn.executescript("DELETE FROM collection_runs; DELETE FROM ml_runs; DELETE FROM alerts; DELETE FROM feeds;")

        feed_ids: dict[str, str] = {}
        for feed in default_feeds():
            feed_ids[feed["name"]] = insert_feed(conn, **feed)

        special_records = [
            ("CISA KEV", "CVE-2024-3400", "CVE-2024-3400 PAN-OS Command Injection", "Critical command injection in Palo Alto Networks PAN-OS GlobalProtect", ["cve", "palo-alto", "command-injection", "kev", "critical"]),
            ("CISA KEV", "CVE-2024-21887", "CVE-2024-21887 Ivanti Connect Secure", "Authentication bypass in Ivanti Connect Secure VPN appliance", ["cve", "ivanti", "auth-bypass", "kev", "critical"]),
            ("MalwareBazaar", "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef", "LockBit 3.0 ransomware sample", "SHA-256 hash of confirmed LockBit 3.0 ransomware binary", ["lockbit", "ransomware", "hash", "critical"]),
            ("Feodo Tracker", "50.16.16.211", "Feodo C2 IP on AWS EC2", "IP enriched as AWS EC2 us-east-1; useful for enrichment demo", ["c2", "feodo", "aws", "botnet"]),
            ("PhishTank", "http://login-microsoft-verify.example-threat.net/session", "Microsoft credential phishing URL", "URL impersonating Microsoft login page", ["phishing", "microsoft", "credential", "url"]),
            ("Abuse.ch URLhaus", "http://payload-store.example-threat.net/update.exe", "URLhaus malware payload", "Malware payload distribution URL", ["urlhaus", "malware", "payload", "exe"]),
        ]
        for idx, (feed_name, value, title, desc, tags) in enumerate(special_records):
            rec = prepare_alert_record(
                feed_id=feed_ids[feed_name],
                feed_name=feed_name,
                indicator_value=value,
                title=title,
                description=desc,
                tags=tags,
                published_at=(datetime.now(timezone.utc) - timedelta(minutes=idx * 8 + 5)).replace(microsecond=0).isoformat(),
            )
            insert_alert_record(conn, rec)

        rng = random.Random(3972)
        feeds = list(feed_ids.items())
        templates = seed_templates()
        created = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        i = 1
        while created < SEED_ALERT_COUNT:
            template = templates[i % len(templates)]
            feed_name, fid = feeds[(i + stable_int(template["title"], len(feeds))) % len(feeds)]
            value = make_indicator_value(template["indicator_type"], i)
            # Avoid duplicate special URL/hash values.
            rec = prepare_alert_record(
                feed_id=fid,
                feed_name=feed_name,
                indicator_value=value,
                indicator_type=template["indicator_type"],
                title=f"{template['title']} #{i}",
                description=template["description"],
                tags=list(template["tags"]),
                published_at=(datetime.now(timezone.utc) - timedelta(minutes=rng.randint(1, 60 * 24 * 35))).replace(microsecond=0).isoformat(),
            )
            ok, _ = insert_alert_record(conn, rec)
            if ok:
                created += 1
            i += 1

        ts = utcnow()
        conn.execute("UPDATE feeds SET last_fetched_at=?, updated_at=? WHERE status='active'", (ts, ts))
        conn.commit()
        logger.info("Seeded demo data: %d feeds, %d alerts", len(feed_ids), created)

# ---------------------------------------------------------------------------
# ML helpers
# ---------------------------------------------------------------------------
def get_alert_training_rows() -> list[dict[str, Any]]:
    with _db_lock, get_conn() as conn:
        rows = conn.execute("SELECT * FROM alerts WHERE mitre_tactic IS NOT NULL").fetchall()
        return [alert_out(row) for row in rows]


def train_ml_model(force: bool = True) -> dict[str, Any]:
    global _ml_model, _ml_metrics
    if not SKLEARN_AVAILABLE:
        _ml_model = None
        _ml_metrics = {
            "available": False,
            "message": "scikit-learn is not installed; heuristic MITRE mapping is active",
            "trained_at": utcnow(),
        }
        return _ml_metrics

    rows = get_alert_training_rows()
    if len(rows) < 20:
        _ml_metrics = {"available": False, "message": "Not enough alerts to train ML model", "trained_at": utcnow()}
        return _ml_metrics

    texts = [ml_text_from_alert(r) for r in rows]
    labels = [r.get("mitre_tactic") or "Discovery" for r in rows]
    unique_labels = sorted(set(labels))
    if len(unique_labels) < 2:
        _ml_metrics = {"available": False, "message": "Need at least two MITRE labels", "trained_at": utcnow()}
        return _ml_metrics

    test_size = 0.25 if len(rows) >= 80 else 0.3
    stratify = labels if min(labels.count(label) for label in unique_labels) >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=test_size,
        random_state=42,
        stratify=stratify,
    )
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=6000)),
        ("clf", MultinomialNB(alpha=0.2)),
    ])
    pipeline.fit(X_train, y_train)
    preds = pipeline.predict(X_test)
    accuracy = float(accuracy_score(y_test, preds))
    macro = float(f1_score(y_test, preds, average="macro"))
    labels_sorted = sorted(set(y_test) | set(preds) | set(labels))
    cm = confusion_matrix(y_test, preds, labels=labels_sorted).tolist()
    report = classification_report(y_test, preds, labels=labels_sorted, zero_division=0, output_dict=True)

    model_path = MODEL_DIR / "ioc_tactic_model.joblib"
    joblib.dump(pipeline, model_path)

    with _ml_lock:
        _ml_model = pipeline
        _ml_metrics = {
            "available": True,
            "trained_at": utcnow(),
            "model_path": str(model_path.relative_to(BASE_DIR)),
            "train_size": len(X_train),
            "test_size": len(X_test),
            "labels": labels_sorted,
            "accuracy": round(accuracy, 4),
            "macro_f1": round(macro, 4),
            "confusion_matrix": cm,
            "classification_report": report,
        }

    with _db_lock, get_conn() as conn:
        conn.execute(
            "INSERT INTO ml_runs(id,trained_at,train_size,test_size,accuracy,macro_f1,labels,confusion_matrix,classification_report) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                _ml_metrics["trained_at"],
                len(X_train),
                len(X_test),
                accuracy,
                macro,
                json_dumps(labels_sorted),
                json_dumps(cm),
                json_dumps(report),
            ),
        )
        conn.commit()

    update_ml_predictions_for_all_alerts()
    logger.info("ML model trained: accuracy=%.3f macro_f1=%.3f labels=%d", accuracy, macro, len(labels_sorted))
    return _ml_metrics


def load_ml_model() -> None:
    global _ml_model, _ml_metrics
    model_path = MODEL_DIR / "ioc_tactic_model.joblib"
    if SKLEARN_AVAILABLE and model_path.exists():
        try:
            _ml_model = joblib.load(model_path)
            with _db_lock, get_conn() as conn:
                row = conn.execute("SELECT * FROM ml_runs ORDER BY trained_at DESC LIMIT 1").fetchone()
            _ml_metrics = {
                "available": True,
                "trained_at": row["trained_at"] if row else None,
                "model_path": str(model_path.relative_to(BASE_DIR)),
                "train_size": row["train_size"] if row else None,
                "test_size": row["test_size"] if row else None,
                "accuracy": round(row["accuracy"], 4) if row else None,
                "macro_f1": round(row["macro_f1"], 4) if row else None,
                "labels": json_loads(row["labels"], []) if row else [],
                "confusion_matrix": json_loads(row["confusion_matrix"], []) if row else [],
                "classification_report": json_loads(row["classification_report"], {}) if row else {},
            }
            logger.info("Loaded ML model from %s", model_path)
            return
        except Exception:
            logger.exception("Could not load ML model; retraining")
    train_ml_model(force=True)


def predict_tactic_with_ml(alert_like: dict[str, Any]) -> tuple[str, float, dict[str, float]]:
    with _ml_lock:
        model = _ml_model
    if model is None or not SKLEARN_AVAILABLE:
        tactic, conf = heuristic_predict_tactic(alert_like)
        return tactic, conf, {tactic: conf}
    text = ml_text_from_alert(alert_like)
    try:
        pred = model.predict([text])[0]
        proba_map: dict[str, float] = {}
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba([text])[0]
            classes = list(model.classes_)
            proba_map = {str(cls): round(float(prob), 4) for cls, prob in zip(classes, probs)}
            conf = float(max(probs))
        else:
            conf = 0.7
            proba_map = {str(pred): conf}
        return str(pred), round(conf, 4), proba_map
    except Exception:
        logger.exception("ML prediction failed; using heuristic")
        tactic, conf = heuristic_predict_tactic(alert_like)
        return tactic, conf, {tactic: conf}


def update_ml_predictions_for_all_alerts() -> None:
    """Refresh ML prediction columns without performing extra feed lookups per row."""
    with _db_lock, get_conn() as conn:
        rows = conn.execute("SELECT * FROM alerts").fetchall()
        ts = utcnow()
        updates: list[tuple[str, float, str, str]] = []
        for row in rows:
            data = dict(row)
            data["tags"] = json_loads(data.get("tags"), [])
            tactic, conf, _ = predict_tactic_with_ml(data)
            updates.append((tactic, conf, ts, row["id"]))
        conn.executemany(
            "UPDATE alerts SET ml_tactic=?, ml_confidence=?, updated_at=? WHERE id=?",
            updates,
        )
        conn.commit()

# ---------------------------------------------------------------------------
# Collector helpers
# ---------------------------------------------------------------------------
@dataclass
class ParsedIndicator:
    value: str
    title: str
    description: str
    tags: list[str]


class CollectorScheduler:
    def __init__(self) -> None:
        self.running = False
        self.task: asyncio.Task | None = None
        self.run_count = 0
        self.last_run: str | None = None
        self.last_results: list[dict[str, Any]] = []

    def start(self) -> None:
        if not COLLECTOR_ENABLED:
            logger.info("Collector scheduler disabled by COLLECTOR_ENABLED=0")
            return
        if self.running:
            return
        self.running = True
        self.task = asyncio.create_task(self._loop())
        logger.info("Collector scheduler started: interval=%d minutes", COLLECTOR_INTERVAL_MINUTES)

    async def _loop(self) -> None:
        await asyncio.sleep(1)  # allow app startup to finish
        while self.running:
            try:
                self.last_results = await asyncio.to_thread(run_collection_cycle)
                self.run_count += 1
                self.last_run = utcnow()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Collector cycle failed")
            await asyncio.sleep(max(60, COLLECTOR_INTERVAL_MINUTES * 60))

    def stop(self) -> None:
        self.running = False
        if self.task:
            self.task.cancel()
            self.task = None
        logger.info("Collector scheduler stopped")

    async def trigger(self) -> list[dict[str, Any]]:
        self.last_results = await asyncio.to_thread(run_collection_cycle)
        self.run_count += 1
        self.last_run = utcnow()
        return self.last_results

    def get_status(self) -> dict[str, Any]:
        with _db_lock, get_conn() as conn:
            collectors = [feed_out(row) for row in conn.execute("SELECT * FROM feeds ORDER BY name").fetchall()]
        next_run_in_seconds = None
        if self.last_run and self.running:
            last_dt = parse_dt(self.last_run)
            if last_dt:
                elapsed = (datetime.now(timezone.utc) - last_dt).total_seconds()
                next_run_in_seconds = max(0, COLLECTOR_INTERVAL_MINUTES * 60 - elapsed)
        return {
            "enabled": COLLECTOR_ENABLED,
            "running": self.running,
            "interval_minutes": COLLECTOR_INTERVAL_MINUTES,
            "run_count": self.run_count,
            "last_run": self.last_run,
            "next_run_in_seconds": next_run_in_seconds,
            "collectors": collectors,
            "last_results": self.last_results,
        }



def get_scheduler() -> CollectorScheduler:
    """Return a scheduler instance even when app lifespan was not triggered (e.g. smoke tests)."""
    global _scheduler
    if _scheduler is None:
        init_db()
        seed_demo_data(force=False)
        load_ml_model()
        _scheduler = CollectorScheduler()
    return _scheduler

def extract_values_from_text(text: str, limit: int = 50) -> list[str]:
    values: list[str] = []
    patterns = [
        r"CVE-\d{4}-\d{4,7}",
        r"https?://[^\s,\"'<>]+",
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        r"\b[a-fA-F0-9]{64}\b",
        r"\b[a-fA-F0-9]{40}\b",
        r"\b[a-fA-F0-9]{32}\b",
        r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, text):
            norm = normalize_indicator(match.rstrip(".,);]"))
            if norm not in values:
                values.append(norm)
            if len(values) >= limit:
                return values
    return values


def parse_remote_payload(feed_name: str, payload: str, max_items: int = 35) -> list[ParsedIndicator]:
    values: list[str] = []
    try:
        obj = json.loads(payload)
        if isinstance(obj, dict):
            candidates: list[Any] = []
            for key in ("data", "urls", "indicators", "vulnerabilities", "items", "results"):
                if isinstance(obj.get(key), list):
                    candidates.extend(obj[key])
            if not candidates:
                candidates = [obj]
        elif isinstance(obj, list):
            candidates = obj
        else:
            candidates = []
        for item in candidates[: max_items * 2]:
            if isinstance(item, dict):
                for key in ("ioc", "indicator", "url", "host", "domain", "ip", "ip_address", "sha256_hash", "sha256", "cveID", "cve", "value"):
                    val = item.get(key)
                    if isinstance(val, str) and val.strip():
                        values.append(val)
                if "value" not in item:
                    compact = json.dumps(item, ensure_ascii=False)
                    values.extend(extract_values_from_text(compact, 5))
            elif isinstance(item, str):
                values.extend(extract_values_from_text(item, 5))
    except Exception:
        values.extend(extract_values_from_text(payload, max_items))

    indicators: list[ParsedIndicator] = []
    for raw in values:
        norm = normalize_indicator(raw)
        if not norm or norm.startswith(("http://schemas", "https://schema")):
            continue
        itype = infer_indicator_type(norm)
        title = f"{feed_name} collected {itype.upper()} IoC"
        desc = f"Indicator parsed from {feed_name} remote feed"
        tags = [feed_name.lower().replace(" ", "-"), itype]
        if feed_name == "CISA KEV":
            tags.extend(["cve", "kev", "exploit"])
        if feed_name in {"Abuse.ch URLhaus", "MalwareBazaar", "Feodo Tracker"}:
            tags.append("malware")
        indicators.append(ParsedIndicator(norm, title, desc, tags))
        if len(indicators) >= max_items:
            break
    return indicators


def fallback_indicators_for_feed(feed_name: str, count: int = 28) -> list[ParsedIndicator]:
    base = stable_int(feed_name, 1000)
    templates = seed_templates()
    items: list[ParsedIndicator] = []
    for n in range(count):
        tmpl = templates[(base + n) % len(templates)]
        value = make_indicator_value(tmpl["indicator_type"], base * 100 + n + int(datetime.now(timezone.utc).timestamp() // 3600))
        items.append(ParsedIndicator(
            value=value,
            title=f"{feed_name}: {tmpl['title']}",
            description=tmpl["description"],
            tags=list(set(tmpl["tags"] + ["collector", feed_name.lower().replace(" ", "-")]))
        ))
    return items


def fetch_feed_indicators(feed: dict[str, Any]) -> tuple[list[ParsedIndicator], str | None]:
    url = feed["source_url"]
    if url.startswith("file://"):
        local_path = BASE_DIR / url.replace("file://", "")
        if local_path.exists():
            text = local_path.read_text(encoding="utf-8", errors="ignore")
            return parse_remote_payload(feed["name"], text), None
        return fallback_indicators_for_feed(feed["name"]), "local file not found; used offline fallback"

    if not REMOTE_FEEDS_ENABLED:
        return fallback_indicators_for_feed(feed["name"]), "REMOTE_FEEDS_ENABLED=0; used offline fallback"

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            response = client.get(url, headers={"User-Agent": "ThreatShield-CDIO/2.0"})
            response.raise_for_status()
            indicators = parse_remote_payload(feed["name"], response.text)
            if indicators:
                return indicators, None
            return fallback_indicators_for_feed(feed["name"]), "remote feed returned no parseable IoCs; used fallback"
    except Exception as exc:
        return fallback_indicators_for_feed(feed["name"]), f"remote fetch failed: {exc}; used offline fallback"


def run_collection_cycle() -> list[dict[str, Any]]:
    started = utcnow()
    run_id = str(uuid4())
    logger.info("COLLECT START run_id=%s", run_id)
    summaries: list[dict[str, Any]] = []
    total_new = 0
    total_dupes = 0
    total_errors = 0

    with _db_lock, get_conn() as conn:
        conn.execute(
            "INSERT INTO collection_runs(id,started_at,success,new_count,duplicate_count,error_count,details) VALUES(?,?,?,?,?,?,?)",
            (run_id, started, 0, 0, 0, 0, "[]"),
        )
        feeds = [dict(row) for row in conn.execute("SELECT * FROM feeds WHERE status='active' ORDER BY name").fetchall()]

    for feed in feeds:
        feed_summary = {
            "feed_id": feed["id"],
            "feed_name": feed["name"],
            "success": True,
            "indicators_new": 0,
            "indicators_duplicate": 0,
            "errors": [],
            "used_fallback": False,
        }
        indicators, error_message = fetch_feed_indicators(feed)
        if error_message:
            feed_summary["errors"].append(error_message)
            feed_summary["used_fallback"] = True
        try:
            with _db_lock, get_conn() as conn:
                for item in indicators:
                    rec = prepare_alert_record(
                        feed_id=feed["id"],
                        feed_name=feed["name"],
                        indicator_value=item.value,
                        title=item.title,
                        description=item.description,
                        tags=item.tags,
                    )
                    tactic, conf, _ = predict_tactic_with_ml(rec)
                    rec["ml_tactic"] = tactic
                    rec["ml_confidence"] = conf
                    ok, _ = insert_alert_record(conn, rec)
                    if ok:
                        feed_summary["indicators_new"] += 1
                        if rec["risk_score"] >= ALERT_THRESHOLD:
                            asyncio.run(send_telegram_alert(rec, feed["name"]))
                    else:
                        feed_summary["indicators_duplicate"] += 1
                ts = utcnow()
                conn.execute("UPDATE feeds SET last_fetched_at=?, updated_at=? WHERE id=?", (ts, ts, feed["id"]))
                conn.commit()
        except Exception as exc:
            feed_summary["success"] = False
            feed_summary["errors"].append(str(exc))
            logger.exception("Collector failed for %s", feed["name"])

        summaries.append(feed_summary)
        total_new += feed_summary["indicators_new"]
        total_dupes += feed_summary["indicators_duplicate"]
        total_errors += 0 if feed_summary["success"] else 1

    finished = utcnow()
    with _db_lock, get_conn() as conn:
        conn.execute(
            "UPDATE collection_runs SET finished_at=?, success=?, new_count=?, duplicate_count=?, error_count=?, details=? WHERE id=?",
            (finished, 1 if total_errors == 0 else 0, total_new, total_dupes, total_errors, json_dumps(summaries), run_id),
        )
        conn.commit()
    logger.info("COLLECT COMPLETED run_id=%s new=%d dupes=%d errors=%d", run_id, total_new, total_dupes, total_errors)
    if total_new:
        train_ml_model(force=True)
    return summaries

# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------
async def send_telegram_message(message: str) -> dict[str, Any]:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return {"sent": False, "reason": "TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID not configured"}
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML", "disable_web_page_preview": True}
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            res = await client.post(url, json=payload)
            res.raise_for_status()
            return {"sent": True, "response": res.json()}
    except Exception as exc:
        logger.warning("Telegram send failed: %s", exc)
        return {"sent": False, "reason": str(exc)}


async def send_telegram_alert(record: dict[str, Any], feed_name: str) -> dict[str, Any]:
    message = (
        "🚨 <b>ThreatShield Alert</b>\n"
        f"Severity: <b>{record['severity'].upper()}</b> | Risk: <b>{record['risk_score']}</b>\n"
        f"IoC: <code>{record['indicator_value']}</code> ({record['indicator_type']})\n"
        f"Feed: {feed_name}\n"
        f"MITRE: {record.get('mitre_tactic')} / {record.get('mitre_technique')}\n"
        f"Geo: {record.get('country')} - {record.get('asn')}"
    )
    return await send_telegram_message(message)

# ---------------------------------------------------------------------------
# Analytics helpers
# ---------------------------------------------------------------------------
def count_by(conn: sqlite3.Connection, group_field: str, where: str = "1=1", params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    rows = conn.execute(f"SELECT {group_field} AS name, COUNT(*) AS count FROM alerts WHERE {where} GROUP BY {group_field} ORDER BY count DESC", params).fetchall()
    return [{"name": row["name"] or "Unknown", "count": row["count"]} for row in rows]


def severity_stats(conn: sqlite3.Connection) -> dict[str, int]:
    result = {sev: 0 for sev in SEVERITIES}
    rows = conn.execute("SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity").fetchall()
    for row in rows:
        result[row["severity"]] = row["count"]
    result["total"] = sum(result.values())
    return result


def indicator_type_stats(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT indicator_type, COUNT(*) AS count FROM alerts GROUP BY indicator_type ORDER BY count DESC").fetchall()
    return [{"type": row["indicator_type"], "name": row["indicator_type"], "count": row["count"]} for row in rows]


def timeline_stats(conn: sqlite3.Connection, days: int = 14) -> list[dict[str, Any]]:
    start = datetime.now(timezone.utc).date() - timedelta(days=days - 1)
    rows = conn.execute(
        """
        SELECT substr(published_at, 1, 10) AS day, severity, COUNT(*) AS count
        FROM alerts
        WHERE published_at >= ?
        GROUP BY day, severity
        ORDER BY day ASC
        """,
        (start.isoformat(),),
    ).fetchall()
    by_day: dict[str, dict[str, Any]] = {}
    for offset in range(days):
        day = (start + timedelta(days=offset)).isoformat()
        by_day[day] = {"date": day, "name": day[-5:], "total": 0, **{sev: 0 for sev in SEVERITIES}}
    for row in rows:
        day = row["day"]
        if day in by_day:
            by_day[day][row["severity"]] = row["count"]
            by_day[day]["total"] += row["count"]
    return list(by_day.values())


def heatmap_stats(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT indicator_type, severity, COUNT(*) AS count FROM alerts GROUP BY indicator_type, severity ORDER BY indicator_type"
    ).fetchall()
    matrix: dict[str, dict[str, Any]] = {}
    for itype in INDICATOR_TYPES:
        matrix[itype] = {"indicator_type": itype, **{sev: 0 for sev in SEVERITIES}}
    for row in rows:
        matrix[row["indicator_type"]][row["severity"]] = row["count"]
    return list(matrix.values())


def feed_severity_stats(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT f.name AS feed, a.severity AS severity, COUNT(*) AS count
        FROM alerts a JOIN feeds f ON f.id=a.feed_id
        GROUP BY f.name, a.severity
        ORDER BY f.name
        """
    ).fetchall()
    matrix: dict[str, dict[str, Any]] = {}
    feeds = [row["name"] for row in conn.execute("SELECT name FROM feeds ORDER BY name").fetchall()]
    for feed in feeds:
        matrix[feed] = {"feed": feed, **{sev: 0 for sev in SEVERITIES}}
    for row in rows:
        matrix[row["feed"]][row["severity"]] = row["count"]
    return list(matrix.values())


def top_countries(conn: sqlite3.Connection, limit: int = 15) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT country, country_code, COUNT(*) AS count,
               SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical,
               SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) AS high,
               AVG(latitude) AS latitude, AVG(longitude) AS longitude
        FROM alerts
        WHERE country IS NOT NULL
        GROUP BY country, country_code
        ORDER BY count DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def map_points(conn: sqlite3.Connection, limit: int = 250) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT country, city, country_code, latitude, longitude, severity, indicator_type, attack_vector, COUNT(*) AS count,
               MAX(published_at) AS last_seen
        FROM alerts
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        GROUP BY country, city, country_code, ROUND(latitude,1), ROUND(longitude,1), severity, indicator_type, attack_vector
        ORDER BY count DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    points = []
    for idx, row in enumerate(rows):
        points.append({
            "id": f"map-{idx}",
            "lat": row["latitude"],
            "lng": row["longitude"],
            "latitude": row["latitude"],
            "longitude": row["longitude"],
            "country": row["country"],
            "city": row["city"],
            "country_code": row["country_code"],
            "severity": row["severity"],
            "type": row["indicator_type"],
            "attack_vector": row["attack_vector"],
            "description": f"{row['count']} IoC tại {row['city']}, {row['country']}",
            "count": row["count"],
            "last_seen": row["last_seen"],
        })
    return points


def mitre_coverage(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT mitre_tactic AS tactic,
               COUNT(*) AS rule_based,
               SUM(CASE WHEN ml_tactic=mitre_tactic THEN 1 ELSE 0 END) AS ml_match,
               AVG(ml_confidence) AS ml_confidence
        FROM alerts
        GROUP BY mitre_tactic
        ORDER BY rule_based DESC
        """
    ).fetchall()
    return [
        {
            "tactic": row["tactic"],
            "rule_based": row["rule_based"],
            "ml_model": row["ml_match"],
            "ml_confidence": round(float(row["ml_confidence"] or 0), 3),
        }
        for row in rows
    ]


def attack_vectors(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT attack_vector, COUNT(*) AS count FROM alerts GROUP BY attack_vector ORDER BY count DESC").fetchall()
    return [{"vector": row["attack_vector"] or "Unknown", "value": row["count"], "count": row["count"]} for row in rows]

# ---------------------------------------------------------------------------
# FastAPI lifecycle/app
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scheduler
    logger.info("Starting %s v%s", APP_NAME, APP_VERSION)
    init_db()
    seed_demo_data(force=False)
    load_ml_model()
    _scheduler = CollectorScheduler()
    _scheduler.start()
    yield
    if _scheduler:
        _scheduler.stop()
    logger.info("Shutdown completed")


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="CDIO Threat Intelligence platform with collector, enrichment, MITRE mapping, ML and Telegram alerting.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if CORS_ORIGINS == "*" else [origin.strip() for origin in CORS_ORIGINS.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"success": False, "message": str(exc) if DEBUG_MODE else "Internal server error", "data": None},
    )

# ---------------------------------------------------------------------------
# System endpoints
# ---------------------------------------------------------------------------
@app.get("/", response_model=APIResponse, tags=["System"])
def root() -> APIResponse:
    return api_ok({
        "name": APP_NAME,
        "version": APP_VERSION,
        "docs_url": "/docs",
        "health_url": "/health",
        "modules": ["collector", "pipeline", "enrichment", "mitre", "ml", "dashboard", "telegram"],
        "default_login": {"email": "admin@threatshield.com", "password": "123234345"},
    }, "ThreatShield API is running")


@app.get("/health", response_model=APIResponse, tags=["System"])
def health() -> APIResponse:
    try:
        with _db_lock, get_conn() as conn:
            conn.execute("SELECT 1").fetchone()
            alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        db_status = "connected"
    except Exception as exc:
        alerts = 0
        db_status = f"error: {exc}"
    return api_ok({
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "ok" if db_status == "connected" else "degraded",
        "database": db_status,
        "database_path": str(DB_PATH),
        "alert_count": alerts,
        "ml_available": bool(_ml_metrics.get("available")),
        "timestamp": utcnow(),
    }, "healthy" if db_status == "connected" else "degraded")

# ---------------------------------------------------------------------------
# Dashboard/analytics endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v1/dashboard", response_model=APIResponse, tags=["Dashboard"])
def dashboard() -> APIResponse:
    with _db_lock, get_conn() as conn:
        sev = severity_stats(conn)
        total_alerts = sev["total"]
        active_incidents = conn.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('active','investigating')").fetchone()[0]
        countries = conn.execute("SELECT COUNT(DISTINCT country) FROM alerts WHERE country IS NOT NULL").fetchone()[0]
        total_feeds = conn.execute("SELECT COUNT(*) FROM feeds").fetchone()[0]
        active_feeds = conn.execute("SELECT COUNT(*) FROM feeds WHERE status='active'").fetchone()[0]
        recent_rows = conn.execute(
            "SELECT a.*, f.name AS feed_name FROM alerts a JOIN feeds f ON f.id=a.feed_id ORDER BY a.published_at DESC LIMIT 10"
        ).fetchall()
        recent_alerts = [alert_out(row, row["feed_name"]) for row in recent_rows]
        top_rows = conn.execute(
            "SELECT title, severity, COUNT(*) AS count, MAX(published_at) AS last_seen FROM alerts GROUP BY title, severity ORDER BY MAX(risk_score) DESC, count DESC LIMIT 8"
        ).fetchall()
        data = {
            "metrics": {
                "total_threats": total_alerts,
                "active_incidents": active_incidents,
                "blocked_attacks": conn.execute("SELECT COUNT(*) FROM alerts WHERE status='mitigated'").fetchone()[0],
                "affected_countries": countries,
                "daily_change": {"threats": 12, "incidents": -3, "blocked": 15, "countries": 2},
            },
            "severity_stats": sev,
            "indicator_types": indicator_type_stats(conn),
            "recent_alerts": recent_alerts,
            "latest_alerts": recent_alerts,
            "trend_data": timeline_stats(conn, 14),
            "top_threats": [dict(row) | {"trend": "up" if stable_int(row["title"], 2) else "down"} for row in top_rows],
            "map_points": map_points(conn, 80),
            "top_countries": top_countries(conn, 15),
            "attack_vectors": attack_vectors(conn),
            "mitre_coverage": mitre_coverage(conn),
            "ml_summary": _ml_metrics,
            "total_feeds": total_feeds,
            "active_feeds": active_feeds,
            "inactive_feeds": total_feeds - active_feeds,
            "total_alerts": total_alerts,
            "critical_alerts": sev["critical"],
            "high_alerts": sev["high"],
            "medium_alerts": sev["medium"],
            "low_alerts": sev["low"],
        }
    return api_ok(data, "dashboard loaded")


@app.get("/api/v1/metrics", response_model=APIResponse, tags=["Stats"])
def metrics() -> APIResponse:
    return api_ok(dashboard().data["metrics"], "metrics loaded")


@app.get("/api/v1/stats/severity", response_model=APIResponse, tags=["Stats"])
def stats_severity() -> APIResponse:
    with _db_lock, get_conn() as conn:
        return api_ok(severity_stats(conn), "severity stats")


@app.get("/api/v1/stats/indicator-types", response_model=APIResponse, tags=["Stats"])
def stats_indicator_types() -> APIResponse:
    with _db_lock, get_conn() as conn:
        return api_ok(indicator_type_stats(conn), "indicator type stats")


@app.get("/api/v1/stats/timeline", response_model=APIResponse, tags=["Stats"])
def stats_timeline(days: int = Query(14, ge=1, le=60)) -> APIResponse:
    with _db_lock, get_conn() as conn:
        return api_ok(timeline_stats(conn, days), "timeline stats")


@app.get("/api/v1/stats/heatmap", response_model=APIResponse, tags=["Stats"])
def stats_heatmap() -> APIResponse:
    with _db_lock, get_conn() as conn:
        return api_ok(heatmap_stats(conn), "IoC type x severity heatmap")


@app.get("/api/v1/stats/feed-severity", response_model=APIResponse, tags=["Stats"])
def stats_feed_severity() -> APIResponse:
    with _db_lock, get_conn() as conn:
        return api_ok(feed_severity_stats(conn), "feed severity distribution")


@app.get("/api/v1/stats/countries", response_model=APIResponse, tags=["Stats"])
def stats_countries(limit: int = Query(15, ge=1, le=100)) -> APIResponse:
    with _db_lock, get_conn() as conn:
        return api_ok(top_countries(conn, limit), "top countries")


@app.get("/api/v1/stats/attack-vectors", response_model=APIResponse, tags=["Stats"])
def stats_attack_vectors() -> APIResponse:
    with _db_lock, get_conn() as conn:
        return api_ok(attack_vectors(conn), "attack vectors")


@app.get("/api/v1/map/threats", response_model=APIResponse, tags=["Dashboard"])
def map_threats(limit: int = Query(250, ge=1, le=1000)) -> APIResponse:
    with _db_lock, get_conn() as conn:
        return api_ok(map_points(conn, limit), "map threat points")


@app.get("/api/v1/analytics/summary", response_model=APIResponse, tags=["Stats"])
def analytics_summary() -> APIResponse:
    with _db_lock, get_conn() as conn:
        data = {
            "timeline": timeline_stats(conn, 14),
            "severity_heatmap": heatmap_stats(conn),
            "feed_severity": feed_severity_stats(conn),
            "top_countries": top_countries(conn, 15),
            "map_points": map_points(conn, 250),
            "attack_vectors": attack_vectors(conn),
            "mitre_coverage": mitre_coverage(conn),
            "severity_stats": severity_stats(conn),
            "indicator_types": indicator_type_stats(conn),
            "ml_summary": _ml_metrics,
        }
    return api_ok(data, "analytics summary")

# ---------------------------------------------------------------------------
# Feed CRUD
# ---------------------------------------------------------------------------
@app.get("/api/v1/feeds", response_model=APIResponse, tags=["Feeds"])
def list_feeds(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    status_filter: Literal["active", "inactive"] | None = Query(None, alias="status"),
    q: str | None = Query(None),
) -> APIResponse:
    where = []
    params: list[Any] = []
    if status_filter:
        where.append("status=?")
        params.append(status_filter)
    if q:
        where.append("(name LIKE ? OR source_url LIKE ? OR description LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like])
    where_sql = "WHERE " + " AND ".join(where) if where else ""
    with _db_lock, get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM feeds {where_sql} ORDER BY name LIMIT ? OFFSET ?", (*params, limit, skip)).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM feeds {where_sql}", params).fetchone()[0]
        out = [feed_out(row) for row in rows]
    return api_ok(out, "feeds fetched", {"skip": skip, "limit": limit, "count": len(out), "total": total})


@app.post("/api/v1/feeds", response_model=APIResponse, status_code=status.HTTP_201_CREATED, tags=["Feeds"])
def create_feed(payload: FeedCreate) -> APIResponse:
    try:
        url = payload.resolved_url
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    with _db_lock, get_conn() as conn:
        if conn.execute("SELECT 1 FROM feeds WHERE source_url=?", (url,)).fetchone():
            raise HTTPException(status_code=409, detail="Feed URL already exists")
        fid = insert_feed(conn, payload.name, url, payload.source, payload.description, "active" if payload.enabled else "inactive")
        conn.commit()
        row = get_feed_by_id(conn, fid)
    return api_ok(feed_out(row), "feed created")


@app.get("/api/v1/feeds/{feed_id}", response_model=APIResponse, tags=["Feeds"])
def get_feed(feed_id: str) -> APIResponse:
    with _db_lock, get_conn() as conn:
        row = get_feed_by_id(conn, feed_id)
        if not row:
            raise HTTPException(status_code=404, detail="Feed not found")
    return api_ok(feed_out(row), "feed detail")


@app.patch("/api/v1/feeds/{feed_id}", response_model=APIResponse, tags=["Feeds"])
def update_feed(feed_id: str, payload: FeedUpdate) -> APIResponse:
    updates: list[str] = []
    params: list[Any] = []
    if payload.name is not None:
        updates.append("name=?")
        params.append(payload.name)
    resolved_url = payload.source_url or payload.url
    if resolved_url is not None:
        updates.append("source_url=?")
        params.append(resolved_url)
    if payload.source is not None:
        updates.append("source=?")
        params.append(payload.source)
    if payload.description is not None:
        updates.append("description=?")
        params.append(payload.description)
    status_value = payload.status
    if payload.enabled is not None:
        status_value = "active" if payload.enabled else "inactive"
    if status_value is not None:
        updates.append("status=?")
        params.append(status_value)
    updates.append("updated_at=?")
    params.append(utcnow())
    with _db_lock, get_conn() as conn:
        if not get_feed_by_id(conn, feed_id):
            raise HTTPException(status_code=404, detail="Feed not found")
        conn.execute(f"UPDATE feeds SET {', '.join(updates)} WHERE id=?", (*params, feed_id))
        conn.commit()
        row = get_feed_by_id(conn, feed_id)
    return api_ok(feed_out(row), "feed updated")


@app.delete("/api/v1/feeds/{feed_id}", response_model=APIResponse, tags=["Feeds"])
def delete_feed(feed_id: str) -> APIResponse:
    with _db_lock, get_conn() as conn:
        row = get_feed_by_id(conn, feed_id)
        if not row:
            raise HTTPException(status_code=404, detail="Feed not found")
        conn.execute("DELETE FROM feeds WHERE id=?", (feed_id,))
        conn.commit()
    return api_ok({"id": feed_id, "name": row["name"]}, "feed deleted")

# ---------------------------------------------------------------------------
# Alert CRUD/Search
# ---------------------------------------------------------------------------
@app.get("/api/v1/alerts", response_model=APIResponse, tags=["Alerts"])
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    severity: Literal["critical", "high", "medium", "low"] | None = Query(None),
    indicator_type: str | None = Query(None),
    feed_id: str | None = Query(None),
    status_filter: Literal["active", "investigating", "mitigated"] | None = Query(None, alias="status"),
    q: str | None = Query(None),
) -> APIResponse:
    where = []
    params: list[Any] = []
    if severity:
        where.append("a.severity=?")
        params.append(severity)
    if indicator_type:
        where.append("a.indicator_type=?")
        params.append(indicator_type)
    if feed_id:
        where.append("a.feed_id=?")
        params.append(feed_id)
    if status_filter:
        where.append("a.status=?")
        params.append(status_filter)
    if q:
        where.append("(a.title LIKE ? OR a.description LIKE ? OR a.indicator_value LIKE ? OR a.tags LIKE ? OR a.mitre_tactic LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like, like, like])
    where_sql = "WHERE " + " AND ".join(where) if where else ""
    with _db_lock, get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT a.*, f.name AS feed_name
            FROM alerts a JOIN feeds f ON f.id=a.feed_id
            {where_sql}
            ORDER BY a.published_at DESC
            LIMIT ? OFFSET ?
            """,
            (*params, limit, skip),
        ).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM alerts a JOIN feeds f ON f.id=a.feed_id {where_sql}", params).fetchone()[0]
        out = [alert_out(row, row["feed_name"]) for row in rows]
    return api_ok(out, "alerts fetched", {"skip": skip, "limit": limit, "count": len(out), "total": total})


@app.get("/api/v1/alerts/{alert_id}", response_model=APIResponse, tags=["Alerts"])
def get_alert(alert_id: str) -> APIResponse:
    with _db_lock, get_conn() as conn:
        row = conn.execute("SELECT a.*, f.name AS feed_name FROM alerts a JOIN feeds f ON f.id=a.feed_id WHERE a.id=?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
    return api_ok(alert_out(row, row["feed_name"]), "alert detail")


@app.post("/api/v1/alerts", response_model=APIResponse, status_code=status.HTTP_201_CREATED, tags=["Alerts"])
def create_alert(payload: AlertCreate) -> APIResponse:
    with _db_lock, get_conn() as conn:
        feed = get_feed_by_id(conn, payload.feed_id)
        if not feed:
            raise HTTPException(status_code=404, detail="Feed not found")
        rec = prepare_alert_record(
            feed_id=payload.feed_id,
            feed_name=feed["name"],
            indicator_value=payload.indicator_value,
            indicator_type=payload.indicator_type,
            title=payload.title,
            description=payload.description,
            tags=payload.tags,
            severity=payload.severity,
            confidence=payload.confidence,
            risk_score=payload.risk_score,
        )
        tactic, conf, _ = predict_tactic_with_ml(rec)
        rec["ml_tactic"] = tactic
        rec["ml_confidence"] = conf
        ok, existing = insert_alert_record(conn, rec)
        if not ok:
            raise HTTPException(status_code=409, detail=f"Duplicate indicator: {existing}")
        conn.execute("UPDATE feeds SET last_fetched_at=?, updated_at=? WHERE id=?", (utcnow(), utcnow(), payload.feed_id))
        conn.commit()
        row = conn.execute("SELECT a.*, f.name AS feed_name FROM alerts a JOIN feeds f ON f.id=a.feed_id WHERE a.id=?", (rec["id"],)).fetchone()
    return api_ok(alert_out(row, row["feed_name"]), "alert created")


@app.patch("/api/v1/alerts/{alert_id}", response_model=APIResponse, tags=["Alerts"])
def update_alert(alert_id: str, payload: AlertUpdate) -> APIResponse:
    updates: list[str] = []
    params: list[Any] = []
    for field in ("title", "description", "severity", "status", "confidence", "risk_score"):
        value = getattr(payload, field)
        if value is not None:
            updates.append(f"{field}=?")
            params.append(value)
    if payload.tags is not None:
        updates.append("tags=?")
        params.append(json_dumps(payload.tags))
    updates.append("updated_at=?")
    params.append(utcnow())
    with _db_lock, get_conn() as conn:
        if not conn.execute("SELECT 1 FROM alerts WHERE id=?", (alert_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Alert not found")
        conn.execute(f"UPDATE alerts SET {', '.join(updates)} WHERE id=?", (*params, alert_id))
        conn.commit()
        row = conn.execute("SELECT a.*, f.name AS feed_name FROM alerts a JOIN feeds f ON f.id=a.feed_id WHERE a.id=?", (alert_id,)).fetchone()
    return api_ok(alert_out(row, row["feed_name"]), "alert updated")


@app.delete("/api/v1/alerts/{alert_id}", response_model=APIResponse, tags=["Alerts"])
def delete_alert(alert_id: str) -> APIResponse:
    with _db_lock, get_conn() as conn:
        row = conn.execute("SELECT id,title FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        conn.execute("DELETE FROM alerts WHERE id=?", (alert_id,))
        conn.commit()
    return api_ok(dict(row), "alert deleted")

# ---------------------------------------------------------------------------
# Pipeline/enrichment/MITRE/ML endpoints
# ---------------------------------------------------------------------------
@app.post("/api/v1/pipeline/enrich/{target}", response_model=APIResponse, tags=["Pipeline"])
def enrich_target(target: str) -> APIResponse:
    with _db_lock, get_conn() as conn:
        row = conn.execute("SELECT a.*, f.name AS feed_name FROM alerts a JOIN feeds f ON f.id=a.feed_id WHERE a.id=?", (target,)).fetchone()
    if row:
        data = alert_out(row, row["feed_name"])
        enrichment = enrich_indicator(data["indicator_value"], data["indicator_type"])
        mapping = mitre_mapping(data["indicator_type"], data["title"], data["description"], data["tags"], data["indicator_value"])
        prediction, conf, probs = predict_tactic_with_ml(data)
        return api_ok({**data, "enrichment": enrichment, "mitre": mapping, "ml_prediction": prediction, "ml_confidence": conf, "probabilities": probs}, "alert enriched")

    indicator_type = infer_indicator_type(target)
    enrichment = enrich_indicator(target, indicator_type)
    mapping = mitre_mapping(indicator_type, f"Manual enrich {target}", None, [], target)
    score = score_indicator(target, indicator_type, "Manual", [], mapping["mitre_tactic"], enrichment["reputation"])
    alert_like = {
        "indicator_type": indicator_type,
        "indicator_value": normalize_indicator(target),
        "title": f"Manual enrich {target}",
        "description": "Manual pipeline enrichment",
        "tags": [],
        "risk_score": score["risk_score"],
        **mapping,
    }
    prediction, conf, probs = predict_tactic_with_ml(alert_like)
    return api_ok({
        "indicator_value": normalize_indicator(target),
        "indicator_type": indicator_type,
        "enrichment": enrichment,
        "risk": score,
        "mitre": mapping,
        "ml_prediction": prediction,
        "ml_confidence": conf,
        "probabilities": probs,
    }, "indicator enriched")


@app.get("/api/v1/mitre/matrix", response_model=APIResponse, tags=["MITRE ATT&CK"])
def mitre_matrix() -> APIResponse:
    with _db_lock, get_conn() as conn:
        rows = conn.execute(
            """
            SELECT mitre_tactic, mitre_technique, attack_vector, COUNT(*) AS count,
                   SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) AS high
            FROM alerts
            GROUP BY mitre_tactic, mitre_technique, attack_vector
            ORDER BY count DESC
            """
        ).fetchall()
    data = [dict(row) for row in rows]
    return api_ok(data, "MITRE matrix loaded")


@app.get("/api/v1/ml/status", response_model=APIResponse, tags=["Machine Learning"])
def ml_status() -> APIResponse:
    return api_ok(_ml_metrics, "ML status")


@app.post("/api/v1/ml/train", response_model=APIResponse, tags=["Machine Learning"])
def ml_train() -> APIResponse:
    metrics = train_ml_model(force=True)
    return api_ok(metrics, "ML model trained")


@app.post("/api/v1/ml/predict", response_model=APIResponse, tags=["Machine Learning"])
def ml_predict(payload: MLPredictRequest) -> APIResponse:
    indicator_type = payload.indicator_type or infer_indicator_type(payload.indicator_value)
    feed_name = payload.feed_name
    enrichment = enrich_indicator(payload.indicator_value, indicator_type)
    title = payload.title or f"Manual {indicator_type} prediction"
    description = payload.description or "Manual prediction request"
    mapping = mitre_mapping(indicator_type, title, description, payload.tags, payload.indicator_value)
    score = score_indicator(payload.indicator_value, indicator_type, feed_name, payload.tags, mapping["mitre_tactic"], enrichment["reputation"])
    alert_like = {
        "indicator_type": indicator_type,
        "indicator_value": normalize_indicator(payload.indicator_value),
        "title": title,
        "description": description,
        "tags": payload.tags,
        "attack_vector": mapping["attack_vector"],
        "risk_score": score["risk_score"],
    }
    prediction, conf, probs = predict_tactic_with_ml(alert_like)
    return api_ok({
        "indicator_value": normalize_indicator(payload.indicator_value),
        "indicator_type": indicator_type,
        "risk": score,
        "enrichment": enrichment,
        "rule_based_mitre": mapping,
        "ml_tactic": prediction,
        "ml_confidence": conf,
        "probabilities": probs,
    }, "ML prediction completed")


@app.get("/api/v1/ml/evaluate", response_model=APIResponse, tags=["Machine Learning"])
def ml_evaluate() -> APIResponse:
    with _db_lock, get_conn() as conn:
        rows = conn.execute("SELECT * FROM ml_runs ORDER BY trained_at DESC LIMIT 10").fetchall()
    runs = []
    for row in rows:
        item = dict(row)
        item["labels"] = json_loads(item["labels"], [])
        item["confusion_matrix"] = json_loads(item["confusion_matrix"], [])
        item["classification_report"] = json_loads(item["classification_report"], {})
        runs.append(item)
    return api_ok({"current": _ml_metrics, "runs": runs}, "ML evaluation")

# ---------------------------------------------------------------------------
# Collector/Telegram/debug/export endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v1/collector/status", response_model=APIResponse, tags=["Collector"])
def collector_status() -> APIResponse:
    scheduler = get_scheduler()
    return api_ok(scheduler.get_status(), "collector status")


@app.post("/api/v1/collector/trigger", response_model=APIResponse, tags=["Collector"])
async def collector_trigger() -> APIResponse:
    scheduler = get_scheduler()
    summaries = await scheduler.trigger()
    totals = {
        "new": sum(item.get("indicators_new", 0) for item in summaries),
        "duplicates": sum(item.get("indicators_duplicate", 0) for item in summaries),
        "errors": sum(0 if item.get("success") else 1 for item in summaries),
    }
    return api_ok({"summaries": summaries, "totals": totals}, f"Collection completed: {totals['new']} new / {totals['duplicates']} duplicates / {totals['errors']} errors")


@app.get("/api/v1/collector/history", response_model=APIResponse, tags=["Collector"])
def collector_history(limit: int = Query(20, ge=1, le=100)) -> APIResponse:
    with _db_lock, get_conn() as conn:
        rows = conn.execute("SELECT * FROM collection_runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
    history = []
    for row in rows:
        item = dict(row)
        item["success"] = bool(item["success"])
        item["details"] = json_loads(item["details"], [])
        history.append(item)
    return api_ok(history, "collector history")


@app.post("/api/v1/telegram/test", response_model=APIResponse, tags=["Telegram"])
async def telegram_test(payload: TelegramTestRequest | None = Body(default=None)) -> APIResponse:
    message = payload.message if payload and payload.message else "✅ ThreatShield Telegram test alert from CDIO demo"
    result = await send_telegram_message(message)
    return api_ok(result, "telegram test completed")


@app.post("/api/v1/ingest/mock", response_model=APIResponse, tags=["Debug"])
def ingest_mock() -> APIResponse:
    summaries = run_collection_cycle()
    return api_ok({"summaries": summaries}, "mock/collector ingest completed")


@app.post("/api/v1/reset", response_model=APIResponse, tags=["Debug"])
def reset_database() -> APIResponse:
    seed_demo_data(force=True)
    metrics = train_ml_model(force=True)
    return api_ok({"seed_alert_count": SEED_ALERT_COUNT, "ml": metrics}, "database reset and re-seeded")


@app.get("/api/v1/export/alerts.csv", tags=["Export"])
@app.get("/api/v1/export/csv", tags=["Export"])
def export_alerts_csv(limit: int = Query(1000, ge=1, le=5000)) -> StreamingResponse:
    with _db_lock, get_conn() as conn:
        rows = conn.execute(
            "SELECT a.*, f.name AS feed_name FROM alerts a JOIN feeds f ON f.id=a.feed_id ORDER BY a.published_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        alerts = [alert_out(row, row["feed_name"]) for row in rows]

    def generate():
        fieldnames = [
            "id", "feed_name", "title", "indicator_type", "indicator_value", "severity", "risk_score",
            "confidence", "status", "country", "asn", "mitre_tactic", "mitre_technique", "ml_tactic", "published_at",
        ]
        from io import StringIO
        buffer = StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)
        for alert in alerts:
            writer.writerow({field: alert.get(field) for field in fieldnames})
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)

    filename = f"threatshield-alerts-{datetime.now().date().isoformat()}.csv"
    return StreamingResponse(generate(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "threatfeeds_backend:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=DEBUG_MODE,
        log_level="debug" if DEBUG_MODE else "info",
    )
