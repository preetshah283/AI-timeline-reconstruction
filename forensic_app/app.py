import os
import json
import uuid
import queue
import threading
import time
from flask import Flask, request, jsonify, render_template, send_file, Response, stream_with_context
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'outputs'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

# Job state store (in-memory; swap for Redis in production)
jobs = {}

# One Queue per job — pipeline worker puts SSE frames in, stream route reads them out
job_queues: dict = {}

# Sentinel signals the SSE generator to stop yielding and close the connection
_SENTINEL = "__STREAM_DONE__"


def _sse(event: str, data: dict) -> str:
    """Format one SSE event frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def emit(job_id: str, event: str, data: dict):
    """Push an SSE event to the browser from anywhere in the pipeline."""
    q = job_queues.get(job_id)
    if q:
        q.put(_sse(event, data))

def run_pipeline(job_id, security_path, system_path, mordor_path, groq_api_key):
    """Run the forensic pipeline in a background thread."""
    job = jobs[job_id]

    def update(stage, pct, msg):
        # Keep the jobs dict in sync (used by /api/result readiness check)
        job['stage']    = stage
        job['progress'] = pct
        job['log'].append(msg)
        # Push live updates to the browser over SSE
        emit(job_id, 'progress', {'stage': stage, 'progress': pct})
        emit(job_id, 'log',      {'message': msg})

    try:
        # ── Lazy imports (heavy libs only loaded when pipeline runs) ──────────
        import pandas as pd
        import json as _json
        import xml.etree.ElementTree as ET
        import re
        import numpy as np
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.gridspec as gridspec
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import LabelEncoder, MinMaxScaler
        from groq import Groq
        from datetime import datetime

        # ── MITRE mappings ────────────────────────────────────────────────────
        MITRE_MAPPINGS = {
            "powershell":  ("T1059.001", "Command and Scripting Interpreter: PowerShell",    "Execution"),
            "wscript":     ("T1059.005", "Command and Scripting Interpreter: VBScript",       "Execution"),
            ".vbs":        ("T1059.005", "Command and Scripting Interpreter: VBScript",       "Execution"),
            "cmd.exe":     ("T1059.003", "Command and Scripting Interpreter: Windows CMD",    "Execution"),
            "mimikatz":    ("T1003.001", "OS Credential Dumping: LSASS Memory",              "Credential Access"),
            "empire":      ("T1059.001", "Command and Scripting Interpreter: PowerShell",    "Execution"),
            "1102":        ("T1070.001", "Indicator Removal: Clear Windows Event Logs",      "Defense Evasion"),
            "7045":        ("T1543.003", "Create or Modify System Process: Windows Service", "Persistence"),
            "conhost":     ("T1059.003", "Command and Scripting Interpreter: Windows CMD",   "Execution"),
            "net.exe":     ("T1069.001", "Permission Groups Discovery: Local Groups",        "Discovery"),
            "whoami":      ("T1033",     "System Owner/User Discovery",                      "Discovery"),
            "schtasks":    ("T1053.005", "Scheduled Task/Job: Scheduled Task",              "Persistence"),
            "reg.exe":     ("T1112",     "Modify Registry",                                  "Defense Evasion"),
        }

        # ── Helpers ───────────────────────────────────────────────────────────
        def evtx_to_json_stream(evtx_file, output_file):
            from Evtx.Evtx import Evtx
            with Evtx(evtx_file) as log:
                with open(output_file, "w", encoding="utf-8") as f:
                    for record in log.records():
                        f.write(_json.dumps(record.xml()) + "\n")

        def parse_event_xml(xml_string):
            event_data = {}
            try:
                root = ET.fromstring(xml_string)
                ns = {'win': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                el = root.find('.//win:EventID', ns)
                if el is not None: event_data['EventID'] = el.text
                el = root.find('.//win:TimeCreated', ns)
                if el is not None: event_data['EventTime'] = el.get('SystemTime')
                el = root.find('.//win:Provider', ns)
                if el is not None: event_data['ProviderName'] = el.get('Name')
                el = root.find('.//win:EventData', ns)
                if el is not None:
                    for d in el.findall('win:Data', ns):
                        if d.get('Name') and d.text:
                            event_data[d.get('Name')] = d.text
                el = root.find('.//win:UserData', ns)
                if el is not None:
                    for child in el:
                        tag = child.tag.split('}')[-1]
                        event_data[tag] = child.text
            except ET.ParseError:
                pass
            return event_data

        # Windows Security/System events rarely carry image paths in the description,
        # so we derive a meaningful process label from EventID + Source instead.
        EVENT_ID_PROCESS_MAP = {
            '4688': 'process-creation',
            '4624': 'logon',
            '4625': 'logon-failure',
            '4634': 'logoff',
            '4648': 'explicit-logon',
            '4672': 'special-logon',
            '4698': 'schtask-created',
            '4702': 'schtask-modified',
            '4720': 'user-created',
            '4726': 'user-deleted',
            '4732': 'group-member-added',
            '4776': 'credential-validation',
            '4768': 'kerberos-tgt',
            '4769': 'kerberos-service',
            '1102': 'eventlog-cleared',
            '7045': 'service-installed',
            '7036': 'service-state-change',
            '7040': 'service-start-type-change',
            '6005': 'eventlog-started',
            '6006': 'eventlog-stopped',
            '6013': 'system-uptime',
            '1':    'process-create-sysmon',
            '3':    'network-connect-sysmon',
            '11':   'file-create-sysmon',
        }

        def extract_process(row):
            desc = str(row.get('Description', ''))
            eid  = str(row.get('EventID', ''))
            src  = str(row.get('Source', ''))

            # 1. Try to find an .exe path in the description (Sysmon / Mordor events)
            m = re.search(r'[\\/]([^\\/]+\.exe)', desc, re.IGNORECASE)
            if m: return m.group(1).lower()
            m = re.search(r'([A-Za-z0-9_\-]+\.exe)', desc, re.IGNORECASE)
            if m: return m.group(1).lower()

            # 2. Map EventID to a human-readable process label
            if eid in EVENT_ID_PROCESS_MAP:
                return EVENT_ID_PROCESS_MAP[eid]

            # 3. Derive label from the provider/source name
            if src and src.lower() not in ('unknown', 'nan', ''):
                # e.g. "Microsoft-Windows-Security-Auditing" → "security-auditing"
                parts = src.split('-')
                return parts[-1].lower() if len(parts) > 1 else src.lower()[:24]

            return "unknown"

        def hunt_threats(row):
            desc = str(row['Description']).lower()
            source = str(row['Source']).lower()
            event_id = str(row['EventID'])
            if event_id == '1102': return "CRITICAL: Audit Logs Cleared (Defense Evasion)"
            if event_id == '7045': return "WARNING: New Service Installed (Potential Persistence)"
            for kw in ['powershell', 'cmd.exe', '.vbs', 'empire', 'mimikatz']:
                if kw in desc: return f"ALERT: Suspicious Keyword ({kw})"
            if event_id == '1' and 'sysmon' in source: return "INFO: Process Created"
            return "Normal"

        def map_to_mitre(row):
            desc = str(row["Description"]).lower()
            eid = str(row["EventID"])
            if eid in MITRE_MAPPINGS:
                t, n, tac = MITRE_MAPPINGS[eid]
                return pd.Series([t, n, tac])
            for kw, (t, n, tac) in MITRE_MAPPINGS.items():
                if kw in desc: return pd.Series([t, n, tac])
            return pd.Series(["—", "Unclassified Activity", "Unknown"])

        def build_attack_chains(df, gap=2):
            df = df.sort_values("Timestamp").copy()
            chain_id, chains, prev = 0, [], None
            for _, row in df.iterrows():
                curr = row["Timestamp"]
                if prev is None or (curr - prev) > pd.Timedelta(minutes=gap):
                    chain_id += 1
                chains.append(chain_id)
                prev = curr
            df["AttackChainID"] = chains
            return df

        out_dir = os.path.join(app.config['OUTPUT_FOLDER'], job_id)
        os.makedirs(out_dir, exist_ok=True)

        # ── Stage 1: Ingest ───────────────────────────────────────────────────
        update("Ingesting logs", 5, "Converting Security EVTX to JSON...")
        sec_json = os.path.join(out_dir, "security.json")
        evtx_to_json_stream(security_path, sec_json)

        update("Ingesting logs", 12, "Converting System EVTX to JSON...")
        sys_json = os.path.join(out_dir, "system.json")
        evtx_to_json_stream(system_path, sys_json)

        update("Ingesting logs", 18, "Loading and parsing log files...")
        df_sec_raw = pd.read_json(sec_json, lines=True)
        df_sys_raw = pd.read_json(sys_json, lines=True)

        sec_parsed = df_sec_raw[0].apply(parse_event_xml)
        df_sec = pd.DataFrame(sec_parsed.tolist())
        sys_parsed = df_sys_raw[0].apply(parse_event_xml)
        df_sys = pd.DataFrame(sys_parsed.tolist())

        # Fields that carry meaningful forensic signal — included in description
        # so keyword rules and MITRE mappings can match against real event data.
        RICH_FIELDS = [
            'Image', 'CommandLine', 'ParentImage', 'ParentCommandLine',
            'TargetImage', 'SourceImage', 'ServiceName', 'ImagePath',
            'NewProcessName', 'ProcessName', 'TargetFilename',
            'SubjectUserName', 'TargetUserName', 'WorkstationName',
        ]

        for df_, etype in [(df_sec, 'Security Event'), (df_sys, 'System Event')]:
            df_['Timestamp'] = pd.to_datetime(df_['EventTime'])
            df_.drop(columns=['EventTime'], inplace=True)
            df_['EventType'] = etype

            # Build a rich description by appending any available forensic fields.
            # Falls back to the generic string if none are present (e.g. plain System events).
            def build_description(row, etype=etype):
                base = f"{etype.split()[0]} event ID {row.get('EventID','')} from {row.get('ProviderName','')}"
                extras = []
                for field in RICH_FIELDS:
                    val = row.get(field)
                    if val and str(val).strip().lower() not in ('nan', 'none', ''):
                        extras.append(str(val))
                if extras:
                    return base + ' | ' + ' | '.join(extras)
                return base

            df_['Description'] = df_.apply(build_description, axis=1)
            df_.rename(columns={'ProviderName': 'Source'}, inplace=True)

        # Mordor (optional)
        df_mordor_norm = pd.DataFrame()
        if mordor_path and os.path.exists(mordor_path):
            update("Ingesting logs", 22, "Loading Mordor simulation data...")
            df_m = pd.read_json(mordor_path, lines=True)
            df_mordor_norm['Timestamp'] = pd.to_datetime(df_m.get('EventTime', pd.Series(dtype='datetime64[ns]')))
            df_mordor_norm['EventType'] = 'Mordor Attack Simulation'
            df_mordor_norm['Source'] = df_m.get('Channel', 'Unknown')
            df_mordor_norm['EventID'] = df_m.get('EventID', pd.Series(0, index=df_m.index))
            target = df_m.get('TargetFilename', pd.Series(dtype='str'))
            image = df_m.get('Image', pd.Series(dtype='str'))
            df_mordor_norm['Description'] = 'Activity: ' + target.fillna(image).fillna('Unknown')

        common = ['Timestamp', 'EventType', 'Source', 'EventID', 'Description']
        frames = [df_sec[common], df_sys[common]]
        if not df_mordor_norm.empty:
            frames.append(df_mordor_norm[common])
        df_unified = pd.concat(frames, ignore_index=True)
        df_unified['Timestamp'] = pd.to_datetime(df_unified['Timestamp'], utc=True)
        # df_unified = df_unified.sort_values(['Timestamp']).reset_index(drop=True)
        df_unified = df_unified.sort_values(['Timestamp']).reset_index(drop=True)  # type: ignore

        total_events = len(df_unified)
        update("Ingesting logs", 28, f"Unified {total_events:,} events from all sources.")

        # ── Stage 2: Threat hunting ───────────────────────────────────────────
        update("Threat hunting", 32, "Running threat hunting rule engine...")
        df_unified['Alert'] = df_unified.apply(hunt_threats, axis=1)
        df_unified[["MITRE_ID", "MITRE_Technique", "MITRE_Tactic"]] = df_unified.apply(map_to_mitre, axis=1)

        suspicious_count = int((df_unified['Alert'] != 'Normal').sum())
        mitre_unique = int((df_unified['MITRE_ID'] != '—').nunique())
        update("Threat hunting", 42, f"Found {suspicious_count} suspicious events. {mitre_unique} MITRE techniques identified.")

        # ── Stage 3: ML anomaly detection ─────────────────────────────────────
        update("ML detection", 48, "Building ML feature matrix...")

        # Filter out known benign periodic/infrastructure events before ML.
        # These fire on fixed schedules so their TimeDelta is always an outlier,
        # causing Isolation Forest to flag them as anomalous — they are not.
        NOISE_EVENT_IDS = {
            '6013',  # System uptime log — fires every 24 h
            '6005',  # EventLog service started — normal boot event
            '6006',  # EventLog service stopped — normal shutdown
        }
        ml_df = df_unified[~df_unified['EventID'].astype(str).isin(NOISE_EVENT_IDS)].copy()
        total_after_filter = len(ml_df)
        event_enc = LabelEncoder()
        source_enc = LabelEncoder()
        ml_df["EventID_encoded"] = event_enc.fit_transform(ml_df["EventID"].astype(str))
        ml_df["Source_encoded"] = source_enc.fit_transform(ml_df["Source"].astype(str))
        ml_df["Time_numeric"] = pd.to_datetime(ml_df["Timestamp"], utc=True).astype("int64") // 10**9
        ml_df = ml_df.sort_values(by="Timestamp").reset_index(drop=True)  # type: ignore[assignment]
        ml_df["TimeDelta"] = ml_df["Time_numeric"].diff().fillna(0).clip(upper=3600)
        ml_df["ProcessName"] = ml_df.apply(extract_process, axis=1)
        proc_enc = LabelEncoder()
        ml_df["ProcessName_encoded"] = proc_enc.fit_transform(ml_df["ProcessName"])

        feature_cols = ["EventID_encoded", "Source_encoded", "ProcessName_encoded", "Time_numeric", "TimeDelta"]
        X = ml_df[feature_cols]

        update("ML detection", 58, "Training Isolation Forest (200 estimators)...")
        model = IsolationForest(contamination="auto", n_estimators=200, random_state=42, n_jobs=-1)
        ml_df["AnomalyScore_raw"] = model.fit_predict(X)
        ml_df["AnomalyScore_confidence"] = model.decision_function(X)
        scaler = MinMaxScaler(feature_range=(0, 100))
        ml_df["RiskScore"] = scaler.fit_transform(-ml_df["AnomalyScore_confidence"].values.reshape(-1, 1)).flatten().round(1)

        anomaly_count = int((ml_df["AnomalyScore_raw"] == -1).sum())
        anomaly_rate = round(anomaly_count / total_events * 100, 2)
        update("ML detection", 68, f"Anomaly detection complete: {anomaly_count} anomalies ({anomaly_rate}%)")

        # Derived metrics
        overlap = int(((ml_df['Alert'] != 'Normal') & (ml_df['AnomalyScore_raw'] == -1)).sum())
        alert_total = int((ml_df['Alert'] != 'Normal').sum())
        overlap_pct = round(overlap / alert_total * 100, 1) if alert_total > 0 else 0
        avg_risk = round(float(ml_df[ml_df['AnomalyScore_raw'] == -1]['RiskScore'].mean()), 1)

        # ── Stage 4: Attack chains ─────────────────────────────────────────────
        update("Attack chains", 72, "Identifying attack chains...")
        threat_df = ml_df[ml_df['Alert'] != 'Normal'].copy()
        threat_df['RiskScore'] = ml_df.loc[threat_df.index, 'RiskScore'].values
        threat_df = build_attack_chains(threat_df)

        chain_risk = threat_df.groupby("AttackChainID").agg(
            EventCount=("Timestamp", "count"),
            AvgRiskScore=("RiskScore", "mean"),
            MaxRiskScore=("RiskScore", "max"),
            Techniques=("MITRE_ID", lambda x: list(x.dropna().unique())),
            Tactics=("MITRE_Tactic", lambda x: list(x.dropna().unique()))
        ).sort_values("EventCount", ascending=False)

        chain_count = int(threat_df['AttackChainID'].nunique())
        update("Attack chains", 78, f"Identified {chain_count} attack chains.")

        # ── Stage 5: Dashboard chart ───────────────────────────────────────────
        update("Generating dashboard", 82, "Rendering forensic dashboard chart...")
        fig = plt.figure(figsize=(16, 10))
        gs = gridspec.GridSpec(2, 2, figure=fig)

        ax1 = fig.add_subplot(gs[0, :])
        normal_d = ml_df[ml_df["AnomalyScore_raw"] == 1]["TimeDelta"]
        anom_d   = ml_df[ml_df["AnomalyScore_raw"] == -1]["TimeDelta"]
        ax1.hist(normal_d, bins=50, alpha=0.6, color="#2a9d8f", label="Normal Events", density=True)
        ax1.hist(anom_d,   bins=50, alpha=0.7, color="#e63946", label="Anomalous Events", density=True)
        ax1.set_xlabel("Seconds Between Events (TimeDelta)")
        ax1.set_ylabel("Density")
        ax1.set_title("Event Timing Distribution: Normal vs Anomalous", fontweight="bold")
        ax1.legend(); ax1.set_xlim(0, 300)

        ax2 = fig.add_subplot(gs[1, 0])
        colors = ml_df["AnomalyScore_raw"].map({1: "#2a9d8f", -1: "#e63946"})
        ax2.scatter(ml_df["Timestamp"], ml_df["RiskScore"], c=colors, alpha=0.4, s=10)
        ax2.set_xlabel("Time"); ax2.set_ylabel("Risk Score (0–100)")
        ax2.set_title("Risk Score Timeline", fontweight="bold")
        plt.setp(ax2.xaxis.get_majorticklabels(), rotation=30, ha="right")

        ax3 = fig.add_subplot(gs[1, 1])
        tactic_counts = ml_df[ml_df["MITRE_ID"] != "—"]["MITRE_Tactic"].value_counts()
        clrs = ["#e63946", "#f4a261", "#e9c46a", "#2a9d8f", "#457b9d", "#6a4c93"]
        tactic_counts.plot(kind="barh", ax=ax3, color=clrs[:len(tactic_counts)])
        ax3.set_title("MITRE ATT&CK Tactic Distribution", fontweight="bold")
        ax3.set_xlabel("Event Count")

        plt.suptitle("AI Forensic Pipeline — Threat Analysis Dashboard", fontsize=14, fontweight="bold")
        plt.tight_layout()
        chart_path = os.path.join(out_dir, "forensic_dashboard.png")
        plt.savefig(chart_path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        # ── Stage 6: LLM report ───────────────────────────────────────────────
        update("Generating report", 88, "Building forensic context for LLM...")

        top_anomalies = ml_df[ml_df["AnomalyScore_raw"] == -1].nlargest(5, "RiskScore")[
            ["Timestamp", "ProcessName", "MITRE_ID", "MITRE_Technique", "MITRE_Tactic", "RiskScore", "Description"]
        ].to_dict(orient="records")

        technique_summary = ml_df[ml_df["MITRE_ID"] != "—"].groupby(
            ["MITRE_ID", "MITRE_Technique", "MITRE_Tactic"]
        ).size().reset_index(name="count").sort_values("count", ascending=False).head(5).to_dict(orient="records")

        chain_summary = chain_risk.head(3).reset_index().to_dict(orient="records")

        context = {
            "investigation_period": {
                "start": str(ml_df["Timestamp"].min()),
                "end":   str(ml_df["Timestamp"].max())
            },
            "data_sources": ["Security EVTX", "System EVTX"] + (["Mordor simulation"] if not df_mordor_norm.empty else []),
            "total_events_analyzed": total_events,
            "anomalies_detected": anomaly_count,
            "anomaly_rate_percent": anomaly_rate,
            "top_anomalous_events": top_anomalies,
            "mitre_techniques_observed": technique_summary,
            "high_risk_processes": ml_df[ml_df["AnomalyScore_raw"] == -1]["ProcessName"].value_counts().head(5).to_dict(),
            "attack_chain_summary": chain_summary
        }

        update("Generating report", 92, "Calling Groq LLM to generate forensic report...")
        client = Groq(api_key=groq_api_key)
        prompt = f"""You are a senior digital forensics analyst writing an official incident investigation report.

EVIDENCE SUMMARY:
{json.dumps(context, indent=2, default=str)}

Write the report in the following structure:

# FORENSIC INVESTIGATION REPORT
**Classification:** Confidential
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## 1. Executive Summary
## 2. Investigation Timeline
## 3. Threat Actor Behavior Analysis
## 4. Key Indicators of Compromise (IOCs)
## 5. Attack Chain Reconstruction
## 6. Risk Assessment
## 7. Recommended Immediate Actions
## 8. Analyst Notes

Write like a senior analyst. Reference MITRE techniques by ID. Be specific about timestamps and processes."""

        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4000
        )
        report_text = resp.choices[0].message.content
        if report_text is None:
            report_text = "Report generation failed: LLM returned empty response."

        report_path = os.path.join(out_dir, "forensic_report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        # Tactic distribution for UI
        tactic_dist = ml_df[ml_df["MITRE_ID"] != "—"]["MITRE_Tactic"].value_counts().to_dict()
        alert_dist  = ml_df["Alert"].value_counts().to_dict()

        # Top processes
        top_procs = ml_df[ml_df["AnomalyScore_raw"] == -1]["ProcessName"].value_counts().head(5).to_dict()

        # Attack chain table
        chain_table = chain_risk.head(5).reset_index().to_dict(orient="records")

        # ── Done ──────────────────────────────────────────────────────────────
        update("Complete", 100, "Pipeline complete!")
        job['status'] = 'done'
        job['result'] = {
            "total_events": total_events,
            "anomaly_count": anomaly_count,
            "anomaly_rate": anomaly_rate,
            "suspicious_count": suspicious_count,
            "mitre_unique": mitre_unique,
            "chain_count": chain_count,
            "overlap_pct": overlap_pct,
            "avg_risk_score": avg_risk,
            "tactic_distribution": tactic_dist,
            "alert_distribution": alert_dist,
            "top_processes": top_procs,
            "chain_table": chain_table,
            "report": report_text,
            "chart_path": chart_path,
            "report_path": report_path,
        }
        # Tell the browser the stream is finished — triggers loadResults()
        emit(job_id, 'done', {})

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        job['status'] = 'error'
        job['error']  = str(e)
        job['log'].append(f"ERROR: {e}")
        job['log'].append(tb)
        emit(job_id, 'log',            {'message': f'ERROR: {e}'})
        emit(job_id, 'pipeline_error', {'error': str(e)})

    finally:
        # Signal the SSE generator to stop and schedule queue cleanup
        q = job_queues.get(job_id)
        if q:
            q.put(_SENTINEL)
        threading.Timer(300, lambda: job_queues.pop(job_id, None)).start()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/run', methods=['POST'])
def run_analysis():
    if 'security_evtx' not in request.files or 'system_evtx' not in request.files:
        return jsonify({'error': 'security_evtx and system_evtx files are required'}), 400

    if not GROQ_API_KEY:
        return jsonify({'error': 'Server is missing GROQ_API_KEY — check your .env file'}), 500

    job_id = str(uuid.uuid4())
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], job_id)
    os.makedirs(upload_dir, exist_ok=True)

    sec_file = request.files['security_evtx']
    sys_file = request.files['system_evtx']
    if not sec_file.filename or not sys_file.filename:
        return jsonify({'error': 'File names are invalid'}), 400
    sec_path = os.path.join(upload_dir, secure_filename(sec_file.filename))
    sys_path = os.path.join(upload_dir, secure_filename(sys_file.filename))
    sec_file.save(sec_path)
    sys_file.save(sys_path)

    # Mordor is a fixed server-side dataset, not user-uploaded
    mordor_path = os.environ.get('MORDOR_JSON_PATH', None)

    jobs[job_id] = {
        'status': 'running',
        'stage': 'Starting',
        'progress': 0,
        'log': [],
        'result': None,
        'error': None
    }

    # Create the SSE queue before the thread starts so the /api/stream route
    # can attach immediately after the client receives the job_id.
    job_queues[job_id] = queue.Queue()

    t = threading.Thread(target=run_pipeline, args=(job_id, sec_path, sys_path, mordor_path, GROQ_API_KEY))
    t.daemon = True
    t.start()

    return jsonify({'job_id': job_id})

@app.route('/api/stream/<job_id>')
def job_stream(job_id):
    """SSE stream — one persistent connection per job, zero polling."""
    if job_id not in job_queues:
        return jsonify({'error': 'Job not found'}), 404

    q = job_queues[job_id]

    def generate():
        KEEP_ALIVE = ": keep-alive\n\n"   # comment line — browsers ignore it
        TIMEOUT    = 15                    # seconds before sending keep-alive

        while True:
            try:
                frame = q.get(timeout=TIMEOUT)
                if frame == _SENTINEL:
                    return              # pipeline done — close the stream
                yield frame
            except queue.Empty:
                yield KEEP_ALIVE       # nothing happened yet — ping the client

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':     'no-cache',
            'X-Accel-Buffering': 'no',   # disable nginx buffering if behind a proxy
        }
    )

@app.route('/api/result/<job_id>')
def job_result(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    if job['status'] != 'done':
        return jsonify({'error': 'Job not complete'}), 400
    result = dict(job['result'])
    result.pop('chart_path', None)
    result.pop('report_path', None)
    return jsonify(result)

@app.route('/api/chart/<job_id>')
def job_chart(job_id):
    job = jobs.get(job_id)
    if not job or job['status'] != 'done':
        return jsonify({'error': 'Not ready'}), 404
    return send_file(job['result']['chart_path'], mimetype='image/png')

@app.route('/api/report/download/<job_id>')
def download_report(job_id):
    job = jobs.get(job_id)
    if not job or job['status'] != 'done':
        return jsonify({'error': 'Not ready'}), 404
    return send_file(job['result']['report_path'], as_attachment=True, download_name='forensic_report.md')

if __name__ == '__main__':
    app.run(debug=True, port=5000, threaded=True)
