import json
from collections import Counter
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data" / "otrf"
RAW_DATA_DIR = BASE_DIR / "data" / "raw"


DATASETS = [
    {
        "id": "otrf_mshta_sct",
        "name": "OTRF Atomic - MSHTA SCT execution",
        "path": DATA_DIR / "cmd_mshta_javascript_getobject_sct" / "cmd_mshta_javascript_getobject_sct_2020-10-2202214475.json",
        "category": "Defense evasion",
        "technique": "T1218.005 Mshta",
        "source": "OTRF Security-Datasets",
    },
    {
        "id": "otrf_sam_esentutl",
        "name": "OTRF Atomic - SAM copy via esentutl",
        "path": DATA_DIR / "cmd_sam_copy_esentutl" / "cmd_sam_copy_esentutl_2020-10-1900290001.json",
        "category": "Credential access",
        "technique": "T1003 OS Credential Dumping",
        "source": "OTRF Security-Datasets",
    },
    {
        "id": "otrf_mimikatz_logonpasswords",
        "name": "OTRF Atomic - Mimikatz logonpasswords",
        "path": DATA_DIR / "empire_mimikatz_logonpasswords" / "empire_mimikatz_logonpasswords_2020-08-07103224.json",
        "category": "Credential access",
        "technique": "T1003.001 LSASS Memory",
        "source": "OTRF Security-Datasets",
    },
    {
        "id": "otrf_record_mic",
        "name": "OTRF Atomic - microphone collection",
        "path": DATA_DIR / "msf_record_mic" / "msf_record_mic_2020-06-09225055.json",
        "category": "Collection",
        "technique": "T1123 Audio Capture",
        "source": "OTRF Security-Datasets",
    },
    {
        "id": "otrf_disable_eventlog",
        "name": "OTRF Atomic - event log service modification",
        "path": DATA_DIR / "reg_disable_eventlog_service_startuptype_modification_via_registry" / "reg_disable_eventlog_service_startuptype_modification_via_registry.json",
        "category": "Defense evasion",
        "technique": "T1562.002 Disable Windows Event Logging",
        "source": "OTRF Security-Datasets",
    },
]


SUSPICIOUS_TERMS = {
    "mimikatz": ("Credential access", "CRITICAL", 98),
    "sekurlsa": ("Credential access", "CRITICAL", 96),
    "lsass": ("Credential access", "HIGH", 90),
    "esentutl": ("Credential access", "HIGH", 86),
    "sam": ("Credential access", "HIGH", 82),
    "mshta": ("Defense evasion", "HIGH", 84),
    "javascript:": ("Defense evasion", "HIGH", 83),
    "getobject": ("Defense evasion", "HIGH", 82),
    "wevtutil": ("Defense evasion", "HIGH", 86),
    "eventlog": ("Defense evasion", "HIGH", 80),
    "reg.exe": ("Defense evasion", "MEDIUM", 68),
    "powershell": ("Endpoint behavior", "MEDIUM", 62),
    "net local": ("Discovery", "MEDIUM", 64),
    "audio": ("Collection", "MEDIUM", 58),
    "microphone": ("Collection", "MEDIUM", 58),
}

EVENT_ID_RULES = {
    1102: ("Defense evasion", "CRITICAL", 95, "Security audit log was cleared"),
    4688: ("Endpoint behavior", "MEDIUM", 60, "New process created"),
    4673: ("Unauthorized access", "MEDIUM", 62, "Privileged service was called"),
    4674: ("Unauthorized access", "MEDIUM", 64, "Privileged object operation"),
    4703: ("Unauthorized access", "MEDIUM", 60, "Token right adjusted"),
    5379: ("Credential access", "HIGH", 82, "Credential Manager credentials were read"),
    4624: ("Unauthorized access", "LOW", 35, "Successful logon"),
    4625: ("Unauthorized access", "HIGH", 78, "Failed logon"),
    5156: ("Network telemetry", "LOW", 24, "Allowed network connection"),
    5158: ("Network telemetry", "LOW", 18, "Allowed network bind"),
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def dataset_status() -> List[Dict]:
    items = []
    for dataset in DATASETS:
        path = dataset["path"]
        raw_name = path.with_suffix(".zip").name
        items.append(
            {
                "id": dataset["id"],
                "name": dataset["name"],
                "category": dataset["category"],
                "technique": dataset["technique"],
                "source": dataset["source"],
                "available": path.exists(),
                "event_count": count_jsonl(path) if path.exists() else 0,
                "size_bytes": path.stat().st_size if path.exists() else 0,
                "raw_archive": raw_name if (RAW_DATA_DIR / raw_name).exists() else None,
            }
        )
    return items


@lru_cache(maxsize=32)
def count_jsonl(path: Path, limit: Optional[int] = None) -> int:
    count = 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for count, _ in enumerate(handle, start=1):
                if limit and count >= limit:
                    break
    except OSError:
        return 0
    return count


def iter_jsonl(path: Path, max_events: int) -> Iterable[Dict]:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for index, line in enumerate(handle):
            if index >= max_events:
                break
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def normalize_event(event: Dict, dataset: Dict, row_index: int) -> Dict:
    event_id = safe_int(event.get("EventID"))
    category, severity, risk_score, rule = EVENT_ID_RULES.get(
        event_id,
        (dataset["category"], "LOW", 25, "Windows event"),
    )

    haystack = " ".join(
        str(event.get(key) or "")
        for key in ["Message", "CommandLine", "ProcessName", "NewProcessName", "Application", "ParentProcessName"]
    ).lower()

    matched_terms = []
    for term, (term_category, term_severity, term_score) in SUSPICIOUS_TERMS.items():
        if term in haystack:
            matched_terms.append(term)
            if term_score > risk_score:
                category = term_category
                severity = term_severity
                risk_score = term_score

    title = build_title(event, rule, matched_terms, dataset)
    timestamp = event.get("@timestamp") or event.get("TimeCreated") or datetime.utcnow().isoformat()
    process = event.get("NewProcessName") or event.get("ProcessName") or event.get("Application")
    user = event.get("SubjectUserName") or event.get("TargetUserName") or event.get("User") or "unknown"
    host = event.get("Hostname") or event.get("Computer") or "unknown"
    command = event.get("CommandLine") or event.get("Message") or ""

    return {
        "id": f"{dataset['id']}-{row_index + 1}",
        "dataset_id": dataset["id"],
        "dataset_name": dataset["name"],
        "timestamp": timestamp,
        "event_id": event_id,
        "category": category,
        "severity": severity,
        "risk_score": min(risk_score, 99),
        "confidence": min(risk_score + 2, 99),
        "title": title,
        "source": event.get("SourceName") or event.get("Channel") or dataset["source"],
        "host": host,
        "user": user,
        "process": process,
        "command_line": command[:700],
        "src_ip": event.get("SourceAddress"),
        "dst_ip": event.get("DestAddress"),
        "mitre_technique": dataset["technique"],
        "summary": summarize_event(event, dataset, category, matched_terms),
        "raw": event,
    }


def build_title(event: Dict, rule: str, matched_terms: List[str], dataset: Dict) -> str:
    process = event.get("NewProcessName") or event.get("ProcessName") or event.get("Application")
    process_name = Path(process).name if process else None
    if matched_terms:
        return f"{dataset['category']}: {matched_terms[0]} observed"
    if process_name:
        return f"{rule}: {process_name}"
    return rule


def summarize_event(event: Dict, dataset: Dict, category: str, matched_terms: List[str]) -> str:
    host = event.get("Hostname") or "unknown host"
    user = event.get("SubjectUserName") or event.get("TargetUserName") or "unknown user"
    technique = dataset["technique"]
    if matched_terms:
        terms = ", ".join(matched_terms[:3])
        return f"{dataset['source']} event on {host} matched {terms}; mapped to {technique}."
    return f"{category} event on {host} for {user}; mapped to {technique}."


def safe_int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def load_events(dataset_id: Optional[str] = None, max_events: int = 1200) -> List[Dict]:
    selected = [dataset for dataset in DATASETS if dataset_id in (None, "all", dataset["id"])]
    if not selected:
        return []

    per_dataset = max(1, max_events // len(selected))
    events: List[Dict] = []
    for dataset in selected:
        path = dataset["path"]
        if not path.exists():
            continue
        for index, event in enumerate(iter_jsonl(path, per_dataset)):
            events.append(normalize_event(event, dataset, index))

    events.sort(key=lambda item: item["timestamp"], reverse=True)
    return events[:max_events]


def build_security_feed(events: List[Dict]) -> Dict:
    if not events:
        return {}

    top_events = sorted(events, key=lambda item: item["risk_score"], reverse=True)[:8]
    signals = [event_to_signal(event) for event in top_events[:5]]
    category_counts = Counter(event["category"] for event in events)
    coverage = [
        {
            "name": category,
            "value": min(99, 45 + count * 4),
        }
        for category, count in category_counts.most_common(6)
    ]

    overall_risk = max(event["risk_score"] for event in events)
    active_incidents = len([event for event in top_events if event["severity"] in ["HIGH", "CRITICAL"]])
    timeline = [
        {
            "time": format_time(event["timestamp"]),
            "event": f"{event['title']} on {event['host']}",
        }
        for event in top_events[:6]
    ]

    return {
        "mode": "defend",
        "dataset_mode": True,
        "dataset_source": "OTRF Security-Datasets",
        "overall_risk": overall_risk,
        "risk_level": "CRITICAL" if overall_risk >= 90 else "HIGH" if overall_risk >= 75 else "MEDIUM",
        "mean_detect_time_seconds": 0.54,
        "blocked_data_gb": round(active_incidents * 0.27, 2),
        "protected_assets": len(set(event["host"] for event in events)),
        "active_incidents": active_incidents,
        "signals": signals,
        "timeline": timeline,
        "coverage": coverage,
        "last_update": datetime.utcnow().isoformat(),
        "event_count": len(events),
    }


def event_to_signal(event: Dict) -> Dict:
    factors = [
        {"name": "Risk score", "weight": event["risk_score"]},
        {"name": "AI confidence", "weight": event["confidence"]},
        {"name": "Event severity", "weight": severity_weight(event["severity"])},
    ]
    evidence = [
        f"Dataset: {event['dataset_name']}",
        f"Host/User: {event['host']} / {event['user']}",
        f"MITRE: {event['mitre_technique']}",
    ]
    if event.get("process"):
        evidence.append(f"Process: {event['process']}")
    if event.get("command_line"):
        evidence.append(f"Command: {event['command_line'][:220]}")

    return {
        "id": event["id"],
        "category": map_category(event["category"]),
        "title": event["title"],
        "severity": event["severity"],
        "confidence": event["confidence"],
        "risk_score": event["risk_score"],
        "source": f"{event['host']} / EventID {event['event_id']}",
        "summary": event["summary"],
        "evidence": evidence[:5],
        "factors": factors,
        "recommended_actions": recommended_actions(event),
        "status": "Dataset replay",
        "detected_at": event["timestamp"],
    }


def map_category(category: str) -> str:
    if category in ["Credential access", "Unauthorized access"]:
        return "Unauthorized access"
    if category == "Collection":
        return "Data leak prevention"
    if category == "Defense evasion":
        return "Endpoint behavior"
    return category


def recommended_actions(event: Dict) -> List[str]:
    category = event["category"]
    if category == "Credential access":
        return ["Isolate host", "Reset exposed credentials", "Collect LSASS evidence"]
    if category == "Defense evasion":
        return ["Restore logging policy", "Open SOC incident", "Hunt related processes"]
    if category == "Unauthorized access":
        return ["Require step-up MFA", "Review privilege use", "Revoke active tokens"]
    if category == "Collection":
        return ["Block data transfer", "Notify data owner", "Preserve audit trail"]
    if category == "Discovery":
        return ["Review account enumeration", "Correlate lateral movement", "Watch host"]
    return ["Open SOC incident", "Collect triage package", "Prepare incident report"]


def severity_weight(severity: str) -> int:
    return {"LOW": 35, "MEDIUM": 62, "HIGH": 84, "CRITICAL": 96}.get(severity, 50)


def format_time(value: str) -> str:
    try:
        return value.replace("T", " ").split(".")[0].split(" ")[-1]
    except Exception:
        return datetime.utcnow().strftime("%H:%M:%S")
