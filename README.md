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

## Installation
Clone the repository:

git clone https://github.com/bazoshimegaelle/aiforge-community.git
cd aiforge-community

## Quick start (Windows)
Run a demo scenario:

python aiforge.py --data sample_data\demo2_takeover --out reports_demo2 --eval --eval_csv eval_demo2.csv


## FRSC Overview 

FRCS (Forensic Reconstruction Confidence Score) ranges from 0–100.
It quantifies how strongly observable evidence supports an incident reconstruction when the AI system itself is opaque.

FRCS aggregates four signals:

- Identity (0–30): login, MFA, session continuity

- Network (0–25): proxy/DNS corroboration

- Data movement (0–25): upload, download, external share

- Endpoint (0–20): process and device evidence

Enhanced mode subtracts -8 points for multiple IPs and -6 points for multiple devices. These penalties reflect ambiguity, not guilt.

Scores ≥80 indicate high-confidence reconstruction. Scores <40 indicate insufficient evidence.

The scoring logic is deterministic and fully inspectable in aiforge.py
 
 ## Interpreatation
 | Score  | Meaning                        |
| ------ | ------------------------------ |
| 80–100 | High-confidence reconstruction |
| 60–79  | Moderate confidence            |
| 40–59  | Weak corroboration             |
| <40    | Insufficient evidence          |
 
 FRCS is:

- Deterministic

- Transparent

- Reproducible

The full logic is implemented in aiforge.py.

# Reproducible Evaluation

Three synthetic scenarios are included:

- demo1_normal —> benign activity

- demo2_takeover —> session anomaly

- demo3_shadow_ai_leak —> potential data exposure

python aiforge.py --data sample_data\demo1_normal --out reports_demo1 --eval --eval_csv eval_demo1.csv
python aiforge.py --data sample_data\demo2_takeover --out reports_demo2 --eval --eval_csv eval_demo2.csv
python aiforge.py --data sample_data\demo3_shadow_ai_leak --out reports_demo3 --eval --eval_csv eval_demo3.csv
Run:


Each scenario produces:

- Baseline FRCS

- Enhanced FRCS (with penalties)

- Structured findings

- Per-case timeline

- Evaluation CSV

All datasets are synthetic and safe for publication.

# Example Output (Evaluation Table)
EVALUATION (Baseline vs Enhanced)
EVALUATION (Baseline vs Enhanced)
case                   events        baseline_frcs  enhanced_frcs  delta         findings_count  incident_class
---------------------  ------------  -------------  -------------  ------------  --------------  -------------------------
user=alice|session=S2  10            80             72             -8            3               possible_exfil_or_malware
user=alice|session=S1  1             10             10             0             1               needs_analysis


## Limitations

AIFORGE:

- Does not inspect AI model prompts

- Does not analyze model weights

- Does not perform semantic prompt injection detection

- Depends on completeness and quality of log sources

It reconstructs observable behavior only, and  it demonstrates structured reconstruction under black-box constraints.

## Intended Use

AIFORGE is suitable for:

- Educational use

- Research artifacts

- Security demonstrations

- Log-correlation prototyping

- Reproducible incident reconstruction experiments

It is not production-hardened.

## License

This project is licensed under the GNU Affero General Public License v3.0.

See LICENSE file for details.

## Citation

If referencing this artifact:

Shime, G.Y. 2026. AIFORGE (Community Edition): Operational AI Forensics Without Model Access. GitHub repository. https://github.com/bazoshimegaelle/aiforge-community

## Version

Current release: v1.0.0

## Author

Gaelle Yeo Shime
Independent Researcher
Maryland, USA

