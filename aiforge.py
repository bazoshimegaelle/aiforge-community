#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
AIFORGE (Community Edition)
Operational AI Forensics: Investigate AI-Enabled Incidents Without Model Access

What it does:
- Ingests JSONL logs from IdP, proxy/DNS, endpoint, and SaaS audit sources
- Normalizes into a unified event schema
- Correlates into case-groups (session_id preferred; else user+ip)
- Builds a timeline
- Computes FRCS (Forensic Reconstruction Confidence Score)
  - baseline: components only (no penalties)
  - enhanced: components + inconsistency penalties
- Generates explainable findings
- Writes per-case reports + optional evaluation table + CSV

Run:
  python aiforge.py --data sample_data/demo2_takeover --out reports_demo2 --eval --eval_csv eval_demo2.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------
# Parsing & Normalization
# ---------------------------

def parse_ts(ts: str) -> datetime:
    # Accepts "2026-01-10T14:00:00Z" or ISO-8601 with offset.
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


@dataclass(frozen=True)
class Event:
    ts: datetime
    source: str                # "idp", "proxy", "endpoint", "saas"
    user: Optional[str]
    ip: Optional[str]
    device: Optional[str]
    action: str
    detail: Dict[str, Any]


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def normalize(source: str, row: Dict[str, Any]) -> Event:
    if "ts" not in row:
        raise ValueError(f"Row missing 'ts' in {source}: {row}")
    return Event(
        ts=parse_ts(row["ts"]),
        source=source,
        user=row.get("user"),
        ip=row.get("ip"),
        device=row.get("device"),
        action=row.get("action", "unknown"),
        detail={k: v for k, v in row.items() if k not in {"ts", "user", "ip", "device", "action"}},
    )


# ---------------------------
# Correlation
# ---------------------------

def correlate(events: List[Event]) -> Dict[str, List[Event]]:
    """
    Group by session_id when available; else by user+ip.
    This is deliberately simple and explainable.
    """
    groups: Dict[str, List[Event]] = {}
    for e in events:
        sid = e.detail.get("session_id")
        if sid:
            key = f"user={e.user}|session={sid}"
        else:
            key = f"user={e.user}|ip={e.ip}"
        groups.setdefault(key, []).append(e)

    for k in groups:
        groups[k].sort(key=lambda x: x.ts)
    return groups


# ---------------------------
# Findings engine (Enhanced)
# ---------------------------

SENSITIVE_RE = re.compile(
    r"\b(payroll|staff|customer|ssn|passport|financial|hr|confidential|pii)\b",
    re.IGNORECASE
)

def is_sensitive_object(name: str) -> bool:
    return bool(SENSITIVE_RE.search(name or ""))


def compute_findings(group: List[Event]) -> List[str]:
    findings: List[str] = []

    # IP/Device sets
    ips = [e.ip for e in group if e.ip]
    devices = [e.device for e in group if e.device]
    unique_ips = sorted(set(ips))
    unique_devices = sorted(set(devices))

    # Rapid IP change within 30 minutes (proxy for impossible travel / VPN / relay)
    if len(unique_ips) >= 2:
        first_seen: Dict[str, datetime] = {}
        for e in group:
            if e.ip and e.ip not in first_seen:
                first_seen[e.ip] = e.ts
        tmin, tmax = min(first_seen.values()), max(first_seen.values())
        if tmax - tmin <= timedelta(minutes=30):
            mins = max(1, int((tmax - tmin).total_seconds() // 60))
            findings.append(
                f"Rapid IP change within {mins} minute(s): {', '.join(sorted(first_seen.keys()))} "
                "(possible impossible-travel/VPN/proxy compromise)."
            )

    # Unknown/new device
    if any((d or "").lower().startswith("unknown") for d in unique_devices):
        findings.append("Activity from an 'unknown' device label observed (potential unmanaged/new device).")
    if len(unique_devices) >= 2:
        findings.append(f"Multiple devices observed: {', '.join(unique_devices)}.")

    # Proxy tags
    proxy_events = [e for e in group if e.source == "proxy"]
    tags = sorted({(e.detail.get("tag") or "").strip() for e in proxy_events if (e.detail.get("tag") or "").strip()})
    susp_tags = [t for t in tags if any(x in t.lower() for x in ["suspicious", "mal", "exfil"])]
    if susp_tags:
        findings.append(f"Proxy/security tooling flagged tags: {', '.join(susp_tags)}.")

    # SaaS data movement + external share
    saas_events = [e for e in group if e.source == "saas"]
    for e in saas_events:
        if e.action == "share" and (e.detail.get("target") in {"external", "external_email"}):
            obj = e.detail.get("object", "<unknown>")
            tgt = e.detail.get("target")
            findings.append(f"External sharing event: object='{obj}' target='{tgt}'.")

    for e in saas_events:
        if e.action in {"upload", "download"}:
            obj = e.detail.get("object", "")
            if obj and is_sensitive_object(obj):
                findings.append(f"Sensitive data indicator: {e.action} of '{obj}' (pattern match).")

    # Endpoint clipboard
    endpoint_events = [e for e in group if e.source == "endpoint"]
    if any(e.action in {"clipboard_copy", "clipboard_paste"} for e in endpoint_events):
        findings.append("Clipboard activity observed on endpoint (possible manual data transfer into AI tool).")

    if not findings:
        findings.append("No high-confidence anomalies detected from available telemetry (may require more data).")

    return findings


# ---------------------------
# FRCS (Baseline vs Enhanced)
# ---------------------------

def frcs_components(group: List[Event]) -> Tuple[int, Dict[str, Any]]:
    """
    FRCS components only (no penalties). Used for baseline.
    Components:
      - identity 0..30
      - network  0..25
      - data     0..25
      - endpoint 0..20
    """
    score = 0
    breakdown: Dict[str, Any] = {}

    has_login = any(e.source == "idp" and e.action == "login_success" for e in group)
    has_mfa = any(e.source == "idp" and e.action == "mfa_success" for e in group)
    session_ids = {e.detail.get("session_id") for e in group if e.detail.get("session_id")}
    consistent_session = (len(session_ids) == 1 and len(session_ids) > 0)

    if has_login and has_mfa and consistent_session:
        identity_pts = 30
    elif has_login and has_mfa:
        identity_pts = 22
    elif has_login:
        identity_pts = 12
    else:
        identity_pts = 0
    score += identity_pts
    breakdown["identity"] = {
        "points": identity_pts,
        "has_login": has_login,
        "has_mfa": has_mfa,
        "consistent_session": consistent_session,
    }

    proxy_events = [e for e in group if e.source == "proxy"]
    if len(proxy_events) >= 3:
        net_pts = 25
    elif len(proxy_events) >= 1:
        net_pts = 12
    else:
        net_pts = 0
    score += net_pts
    breakdown["network"] = {"points": net_pts, "proxy_events": len(proxy_events)}

    saas_events = [e for e in group if e.source == "saas"]
    moved = any(e.action in {"upload", "download", "share"} for e in saas_events)
    if moved:
        data_pts = 25
    elif saas_events:
        data_pts = 8
    else:
        data_pts = 0
    score += data_pts
    breakdown["data_movement"] = {"points": data_pts, "saas_events": len(saas_events), "moved": moved}

    endpoint_events = [e for e in group if e.source == "endpoint"]
    if len(endpoint_events) >= 2:
        end_pts = 20
    elif len(endpoint_events) == 1:
        end_pts = 10
    else:
        end_pts = 0
    score += end_pts
    breakdown["endpoint"] = {"points": end_pts, "endpoint_events": len(endpoint_events)}

    return min(score, 100), breakdown


def frcs_enhanced(group: List[Event]) -> Tuple[int, Dict[str, Any]]:
    """
    Enhanced FRCS = base components - inconsistency penalties.
    """
    base, breakdown = frcs_components(group)
    unique_ips = {e.ip for e in group if e.ip}
    unique_devices = {e.device for e in group if e.device}

    penalty = 0
    if len(unique_ips) >= 2:
        penalty += 8
    if len(unique_devices) >= 2:
        penalty += 6

    enhanced = max(0, min(100, base - penalty))
    breakdown["penalties"] = {
        "points_removed": penalty,
        "multi_ip": len(unique_ips) >= 2,
        "multi_device": len(unique_devices) >= 2,
    }
    breakdown["score_base"] = base
    breakdown["score_enhanced"] = enhanced
    return enhanced, breakdown


# ---------------------------
# Classification & Actions (simple heuristics)
# ---------------------------

def classify_incident(group: List[Event]) -> str:
    saas = [e for e in group if e.source == "saas"]
    if any(e.action == "share" and (e.detail.get("target") in {"external", "external_email"}) for e in saas):
        return "potential_data_exposure"

    proxy = [e for e in group if e.source == "proxy"]
    if any("suspicious" in (e.detail.get("tag") or "").lower() for e in proxy):
        return "possible_exfil_or_malware"

    moved = [e for e in saas if e.action in {"upload", "download"}]
    if any(is_sensitive_object(e.detail.get("object", "")) for e in moved):
        return "sensitive_data_movement"

    return "needs_analysis"


def recommended_actions(score: int, incident: str) -> List[str]:
    actions: List[str] = []

    if incident in {"potential_data_exposure", "sensitive_data_movement"}:
        actions += [
            "Verify whether regulated/sensitive data was exposed; initiate notification workflow if required.",
            "Review external shares and revoke access links where possible.",
        ]

    if incident == "possible_exfil_or_malware":
        actions += [
            "Contain suspected exfil: block destinations/domains; isolate impacted endpoints if applicable.",
            "Review proxy/SWG and EDR alerts for the time window; confirm process lineage and persistence indicators.",
        ]

    if score >= 80:
        actions += [
            "Preserve evidence: export relevant logs; retain generated timelines; hash key artifacts.",
            "Revoke session tokens / force re-authentication for impacted accounts.",
            "Confirm scope of data movement (uploads/shares/downloads) and notify stakeholders as needed.",
        ]
    elif score >= 50:
        actions += [
            "Collect additional telemetry to increase confidence (endpoint + SaaS audit + proxy correlation).",
            "Review identity anomalies (new device, rapid IP change, unusual MFA patterns).",
            "Verify whether suspicious integrations or OAuth tokens were created/used.",
        ]
    else:
        actions += [
            "Insufficient evidence: verify logging/retention and re-run correlation after data collection.",
            "Start with IdP + proxy logs to establish access path and minimal timeline.",
        ]

    return actions


# ---------------------------
# Reporting & Evaluation Output
# ---------------------------

def render_timeline(group: List[Event]) -> str:
    lines: List[str] = []
    for e in group:
        extras = []
        for k in ("url", "object", "target", "process", "token_type", "tag"):
            if k in e.detail:
                extras.append(f"{k}={e.detail[k]}")
        extra_str = (" " + " ".join(extras)) if extras else ""
        lines.append(f"{e.ts.isoformat()} [{e.source}] {e.action} user={e.user} ip={e.ip} device={e.device}{extra_str}")
    return "\n".join(lines)


def print_eval_table(rows: List[Dict[str, Any]]) -> None:
    headers = ["case", "events", "baseline_frcs", "enhanced_frcs", "delta", "findings_count", "incident_class"]
    colw = {h: max(len(h), 12) for h in headers}

    for r in rows:
        for h in headers:
            colw[h] = max(colw[h], len(str(r[h])))

    def fmt_line(vals: List[str]) -> str:
        return "  ".join(v.ljust(colw[h]) for v, h in zip(vals, headers))

    print("\nEVALUATION (Baseline vs Enhanced)")
    print(fmt_line(headers))
    print(fmt_line(["-" * colw[h] for h in headers]))
    for r in rows:
        print(fmt_line([str(r[h]) for h in headers]))
    print("")


def write_eval_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["case", "events", "baseline_frcs", "enhanced_frcs", "delta", "findings_count", "incident_class"],
        )
        w.writeheader()
        w.writerows(rows)


# ---------------------------
# Main
# ---------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="AIFORGE - Operational AI Forensics without model access")
    ap.add_argument("--data", type=str, required=True, help="Folder containing JSONL input files")
    ap.add_argument("--out", type=str, default="reports", help="Output folder for per-case reports")
    ap.add_argument("--eval", action="store_true", help="Print baseline vs enhanced evaluation table")
    ap.add_argument("--eval_csv", type=str, default="", help="Write evaluation summary CSV to this path")
    args = ap.parse_args()

    data_dir = Path(args.data)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    sources = {
        "idp": data_dir / "idp.jsonl",
        "proxy": data_dir / "proxy.jsonl",
        "endpoint": data_dir / "endpoint.jsonl",
        "saas": data_dir / "saas_audit.jsonl",
    }

    events: List[Event] = []
    for src, path in sources.items():
        for row in read_jsonl(path):
            events.append(normalize(src, row))

    events.sort(key=lambda e: e.ts)
    groups = correlate(events)

    print(f"Loaded {len(events)} events. Correlated into {len(groups)} case-group(s).")

    eval_rows: List[Dict[str, Any]] = []

    for key, group in groups.items():
        incident = classify_incident(group)

        baseline_score, _ = frcs_components(group)
        enhanced_score, breakdown = frcs_enhanced(group)

        findings = compute_findings(group)
        timeline = render_timeline(group)
        actions = recommended_actions(enhanced_score, incident)

        report_lines: List[str] = []
        report_lines.append(f"CASE: {key}")
        report_lines.append(f"INCIDENT_CLASS: {incident}")
        report_lines.append(f"FRCS_BASELINE: {baseline_score}/100")
        report_lines.append(f"FRCS_ENHANCED: {enhanced_score}/100")
        report_lines.append("")
        report_lines.append("FINDINGS (Enhanced):")
        for fnd in findings:
            report_lines.append(f"- {fnd}")
        report_lines.append("")
        report_lines.append("EVIDENCE_BREAKDOWN (Enhanced):")
        report_lines.append(json.dumps(breakdown, indent=2))
        report_lines.append("")
        report_lines.append("RECOMMENDED_ACTIONS:")
        for a in actions:
            report_lines.append(f"- {a}")
        report_lines.append("")
        report_lines.append("TIMELINE:")
        report_lines.append(timeline)

        safe_name = key.replace("|", "__").replace("=", "_").replace(":", "_").replace("/", "_")
        out_path = out_dir / f"{safe_name}.txt"
        out_path.write_text("\n".join(report_lines), encoding="utf-8")
        print(f"  wrote {out_path}")

        eval_rows.append(
            {
                "case": key,
                "events": len(group),
                "baseline_frcs": baseline_score,
                "enhanced_frcs": enhanced_score,
                "delta": enhanced_score - baseline_score,
                "findings_count": len(findings),
                "incident_class": incident,
            }
        )

    if args.eval:
        print_eval_table(eval_rows)

    if args.eval_csv:
        csv_path = Path(args.eval_csv)
        write_eval_csv(csv_path, eval_rows)
        print(f"Wrote evaluation CSV: {csv_path}")

    print("Done.")


if __name__ == "__main__":
    main()
