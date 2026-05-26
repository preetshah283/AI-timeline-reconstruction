# AI Log Timeline Reconstruction

A Python tool that ingests Windows Event Logs and threat intelligence datasets, normalizes them into a unified schema, and reconstructs a chronological forensic timeline. An AI-generated incident response report is produced automatically using an LLM.

Built for SOC analysts, threat hunters, and incident responders who need to correlate events across multiple log sources quickly.

---

## What It Does

1. **Ingests** Windows Event Logs (`security.evtx`, `system.evtx`) and the [Mordor threat dataset](https://github.com/OTRF/Security-Datasets)
2. **Normalizes** all events into a unified schema regardless of source format
3. **Correlates** events chronologically across sources into a single forensic timeline
4. **Exports** `timeline.csv` — a clean, analyst-ready artifact
5. **Generates** a natural-language incident response report via Groq API (Llama 3)

---

## Pipeline

```
security.evtx  ─┐
system.evtx    ─┼──► EVTX → JSON ──► Normalize ──► Merge & Sort ──► timeline.csv
Mordor dataset ─┘                                                         │
                                                                          ▼
                                                              Groq API (Llama 3)
                                                                          │
                                                                          ▼
                                                          incident_report.txt
```

---

## Sample Output

`timeline.csv` columns:

| timestamp | source | event_id | event_type | user | description |
|---|---|---|---|---|---|
| 2024-01-15 03:42:11 | security.evtx | 4625 | Failed Logon | SYSTEM | Account failed to log on |
| 2024-01-15 03:42:14 | security.evtx | 4625 | Failed Logon | SYSTEM | Account failed to log on |
| 2024-01-15 03:42:31 | system.evtx | 7045 | Service Installed | SYSTEM | New service created |
| 2024-01-15 03:43:02 | Mordor | T1053.005 | Scheduled Task | Administrator | Scheduled task created for persistence |

---

## Setup

```bash
git clone https://github.com/preetshah283/ai-log-timeline
cd ai-log-timeline
pip install -r requirements.txt
```

Set your Groq API key:
```bash
export GROQ_API_KEY=your_key_here
```

---

## Usage

```bash
python main.py \
  --security path/to/security.evtx \
  --system path/to/system.evtx \
  --mordor path/to/mordor_dataset.json \
  --output timeline.csv
```

The incident response report is written to `incident_report.txt` automatically.

---

## Stack

| Component | Technology |
|---|---|
| Log parsing | `python-evtx` |
| Data handling | `pandas` |
| LLM inference | Groq API — Llama 3 |
| Threat dataset | Mordor / OTRF Security Datasets |

---

## MITRE ATT&CK Coverage

Events in the timeline are mapped to MITRE ATT&CK techniques where applicable. The Mordor dataset ships with technique IDs; Windows Event Log events are mapped manually based on Event ID.

Example mappings used in this project:

| Event | ATT&CK Technique |
|---|---|
| Multiple failed logons (4625) | T1110 — Brute Force |
| New service installed (7045) | T1543.003 — Windows Service |
| Scheduled task creation | T1053.005 — Scheduled Task |
| Logon with special privileges (4672) | T1078 — Valid Accounts |

Full ATT&CK matrix: [attack.mitre.org](https://attack.mitre.org)

---

## Why This Exists

Manual log correlation during incident response is slow and error-prone. Analysts typically work across multiple tools and formats with no unified view. This tool automates the normalization and correlation step, giving you a single timeline artifact from the moment you run it — and an AI-generated report that summarizes what happened without requiring you to read every row.

---

## Limitations

- Windows Event Logs only (Linux support not implemented)
- Groq API required for report generation (free tier sufficient)
- Mordor dataset must be pre-downloaded separately
