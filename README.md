# ForensIQ — AI Forensic Pipeline Web App

Upload Windows EVTX log files and get a full AI-powered forensic investigation report.

## Quick Start (Local)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the app
python app.py

# 3. Open browser
# http://localhost:5000
```

## Deployment Options

### Option A — Render.com (Free tier, easiest)
1. Push this folder to a GitHub repo
2. Go to https://render.com → New Web Service
3. Connect your repo, set:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
4. Add `gunicorn>=21.0.0` to requirements.txt
5. Deploy — you get a public URL instantly

### Option B — Railway.app
1. Push to GitHub
2. New project → Deploy from GitHub repo
3. Railway auto-detects Flask, sets `python app.py`
4. Add environment variable `PORT=5000` if needed

### Option C — VPS / Server (nginx + gunicorn)
```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:5000 --timeout 600 app:app
```
`--timeout 600` is important — pipeline can take several minutes on large EVTX files.

### Option D — Google Colab (for demo)
```python
from google.colab.output import eval_js
from pyngrok import ngrok
import subprocess, threading

subprocess.Popen(['pip','install','-q','flask','python-evtx','groq','scikit-learn'])
threading.Thread(target=lambda: subprocess.run(['python','app.py'])).start()
print(ngrok.connect(5000))
```

## File Structure
```
forensic_app/
├── app.py              # Flask backend + full pipeline
├── requirements.txt
├── templates/
│   └── index.html      # Upload UI + Results dashboard
└── static/
    ├── css/style.css
    └── js/app.js
```

## Usage
1. Upload `security_local.evtx` (required)
2. Upload `system_local.evtx` (required)
3. Upload Mordor simulation JSON (optional)
4. Enter your Groq API key (get one free at console.groq.com)
5. Click **Run Forensic Pipeline**
6. Watch live progress — takes 2–10 min depending on log size
7. View metrics dashboard + download the full forensic report

## Metrics Explained
| Metric | Description |
|---|---|
| Anomaly Rate | % of events Isolation Forest flagged as anomalous |
| Avg Risk Score | Mean 0–100 risk score for anomalous events |
| Rule–ML Agreement | Events caught by BOTH rule engine AND ML (highest confidence) |
| MITRE Techniques | Unique ATT&CK technique IDs observed |
| Attack Chains | Temporal clusters of suspicious events (2-min gap threshold) |

## Notes
- Groq API key is used only for the LLM report generation and is never stored
- Jobs are held in memory — restart clears them (use Redis for production persistence)
- For very large EVTX files (>100MB), increase gunicorn `--timeout` accordingly
