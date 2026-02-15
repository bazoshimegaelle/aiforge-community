# AIFORGE (Community Edition)
Operational AI Forensics: Investigate AI-Enabled Incidents Without Model Access

AIFORGE is a small, runnable CLI tool for reconstructing AI-enabled incidents in SaaS and shadow-AI environments where investigators do not have access to model internals.

It correlates four evidence planes:
- Identity (SSO, MFA, token/session)
- Network (proxy/DNS/SWG)
- Endpoint (process/clipboard)
- SaaS audit (upload/download/share)

Outputs:
- Per-case report files (timeline + FRCS + findings + actions)
- Optional evaluation table (baseline vs enhanced)
- Optional evaluation CSV

## Requirements
- Python 3.10+ (stdlib only)

## Quick start (Windows)
From the repo root:

```bat
python aiforge.py --help

## Design Philosophy

AIFORGE is intentionally:

Small

Inspectable

Reproducible

Vendor-neutral

Non-commercial

It is not a SIEM replacement and does not inspect model internals.
It formalizes disciplined log-based reconstruction under black-box constraints.

## Reproducible Evaluation (CACM Artifact)

Run all included scenarios:

python aiforge.py --data sample_data\demo1_normal --out reports_demo1 --eval --eval_csv eval_demo1.csv
python aiforge.py --data sample_data\demo2_takeover --out reports_demo2 --eval --eval_csv eval_demo2.csv
python aiforge.py --data sample_data\demo3_shadow_ai_leak --out reports_demo3 --eval --eval_csv eval_demo3.csv


Each scenario produces:

Baseline FRCS

Enhanced FRCS (with penalties)

Structured findings

Per-case timeline

Evaluation CSV

##  FRCS Overview

The Forensic Reconstruction Confidence Score (FRCS) is a bounded score (0–100) that quantifies the evidentiary strength of an incident reconstruction when AI model internals are unavailable.

FRCS aggregates four independently observable evidence planes:

1️⃣ Identity Certainty (0–30)

Measures authentication strength and session continuity.

Contributing signals include:

Successful login event

MFA completion

Stable session identifier

Consistent user attribution

Higher values indicate strong post-authentication confidence.

2️⃣ Network Corroboration (0–25)

Measures whether identity activity is supported by network telemetry.

Contributing signals include:

Consistent source IP

Proxy/DNS corroboration

SaaS domain access matching session timeline

Corroboration reduces ambiguity in attribution.

3️⃣ Data Movement (0–25)

Measures observable file interaction or content transfer.

Contributing signals include:

SaaS upload/download events

External sharing events

Network egress to AI/SaaS endpoints

This component indicates whether sensitive data may have been exposed.

4️⃣ Endpoint Confirmation (0–20)

Measures device-level validation of activity.

Contributing signals include:

Browser process execution

Clipboard interaction

Device identifier consistency

Endpoint evidence increases reconstruction fidelity.

Enhanced Mode (Penalty Model)

Enhanced FRCS introduces structured penalties to reflect ambiguity:

−8 points for multiple distinct IP addresses within a session

−8 points for multiple device identifiers within a session

These penalties reflect attribution uncertainty rather than malicious intent.

Interpretation Guidelines

FRCS Range	                         Interpretation
80–100	                           High-confidence reconstruction
60–79	                           Moderate confidence,review recommended
40–59	                           Weak corroboration
<40	                               Insufficient evidence

FRCS is designed to be:

Transparent

Deterministic

Explainable

Reproducible

The scoring logic is fully implemented in aiforge.py and can be independently inspected or modified.

