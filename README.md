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
