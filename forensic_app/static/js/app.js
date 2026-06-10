'use strict';

// ── Screens ───────────────────────────────────────────────────────────────────
const screens = {
  upload:   document.getElementById('upload-screen'),
  progress: document.getElementById('progress-screen'),
  results:  document.getElementById('results-screen'),
};
function showScreen(name) {
  Object.values(screens).forEach(s => s.classList.remove('active'));
  screens[name].classList.add('active');
}

// ── Drop zones ────────────────────────────────────────────────────────────────
document.querySelectorAll('.drop-zone').forEach(zone => {
  const inputName = zone.dataset.input;
  const input = document.getElementById('inp-' + inputName.replace('_evtx','').replace('_json',''));
  const fnEl  = document.getElementById('fn-'  + inputName.replace('_evtx','').replace('_json',''));

  zone.addEventListener('click', () => input && input.click());

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault(); zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file && input) {
      const dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      markFilled(zone, fnEl, file.name);
    }
  });

  if (input) {
    input.addEventListener('change', () => {
      if (input.files[0]) markFilled(zone, fnEl, input.files[0].name);
    });
  }
});

function markFilled(zone, fnEl, name) {
  zone.classList.add('filled');
  if (fnEl) fnEl.textContent = name;
}

// ── Form submit ───────────────────────────────────────────────────────────────
let currentJobId = null;

document.getElementById('upload-form').addEventListener('submit', async e => {
  e.preventDefault();
  const form   = e.target;
  const secFile = form.security_evtx.files[0];
  const sysFile = form.system_evtx.files[0];

  if (!secFile) return alert('Please upload a Security EVTX file.');
  if (!sysFile) return alert('Please upload a System EVTX file.');

  const fd = new FormData(form);
  document.getElementById('run-btn').disabled = true;

  showScreen('progress');

  try {
    const res  = await fetch('/api/run', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    currentJobId = data.job_id;
    pollStatus(currentJobId);
  } catch (err) {
    showScreen('upload');
    document.getElementById('run-btn').disabled = false;
    alert('Failed to start pipeline: ' + err.message);
  }
});

// ── SSE stream (replaces polling) ─────────────────────────────────────────────
// One persistent HTTP connection. Server pushes events whenever state changes.
// Zero wasted requests during slow EVTX conversion — the browser just listens.
function pollStatus(jobId) {
  const stageEl = document.getElementById('prog-stage');
  const barEl   = document.getElementById('prog-bar');
  const pctEl   = document.getElementById('prog-pct');
  const logEl   = document.getElementById('prog-log');

  // Open a single persistent SSE connection to the backend stream endpoint.
  const evtSource = new EventSource('/api/stream/' + jobId);

  // ── progress: update bar + stage label ───────────────────────────────────
  // Server sends this whenever the pipeline advances to a new stage.
  evtSource.addEventListener('progress', e => {
    try {
      const data = JSON.parse(e.data);
      stageEl.textContent = data.stage || 'Working...';
      barEl.style.width   = (data.progress || 0) + '%';
      pctEl.textContent   = (data.progress || 0) + '%';
    } catch (_) {}
  });

  // ── log: append one line to the terminal box ──────────────────────────────
  // Server sends individual lines as they happen — no re-rendering the whole list.
  evtSource.addEventListener('log', e => {
    try {
      const { message } = JSON.parse(e.data);
      const line = document.createElement('div');
      line.className  = 'log-line';
      line.textContent = message;
      logEl.appendChild(line);
      logEl.scrollTop  = logEl.scrollHeight;
    } catch (_) {}
  });

  // ── done: pipeline finished — close stream and paint results ──────────────
  evtSource.addEventListener('done', async () => {
    evtSource.close();
    await loadResults(jobId);
  });

  // ── pipeline_error: backend reported a failure ────────────────────────────
  evtSource.addEventListener('pipeline_error', e => {
    evtSource.close();
    let msg = 'Unknown error';
    try { msg = JSON.parse(e.data).error; } catch (_) {}
    showScreen('upload');
    document.getElementById('run-btn').disabled = false;
    alert('Pipeline error: ' + msg);
  });

  // ── transport error: SSE connection itself dropped ────────────────────────
  // EventSource auto-reconnects by default; only bail on a fully closed state.
  evtSource.onerror = () => {
    if (evtSource.readyState === EventSource.CLOSED) {
      showScreen('upload');
      document.getElementById('run-btn').disabled = false;
      alert('Lost connection to server. Please try again.');
    }
  };
}

// ── Load & render results ─────────────────────────────────────────────────────
async function loadResults(jobId) {
  const [resData] = await Promise.all([
    fetch('/api/result/' + jobId).then(r => r.json()),
  ]);

  // Metric tiles
  setText('m-total',        fmt(resData.total_events));
  setText('m-anomaly',      fmt(resData.anomaly_count));
  setText('m-anomaly-rate', resData.anomaly_rate + '% anomaly rate');
  setText('m-risk',         resData.avg_risk_score ?? '—');
  setText('m-mitre',        resData.mitre_unique);
  setText('m-overlap',      resData.overlap_pct + '%');
  setText('m-chains',       resData.chain_count);

  // Chart
  document.getElementById('dashboard-chart').src = '/api/chart/' + jobId;

  // MITRE tactic bars
  renderBars('mitre-bars', resData.tactic_distribution, [
    '#3b82f6','#e63946','#f4a261','#2a9d8f','#a855f7','#fbbf24'
  ]);

  // Alert bars
  const alertColors = {
    'CRITICAL': '#ff4757','ALERT':'#ff6b81','WARNING':'#ffa502',
    'INFO':'#3b82f6','Normal':'#3a5a40'
  };
  const alertDist = {};
  Object.entries(resData.alert_distribution || {}).forEach(([k, v]) => {
    const key = Object.keys(alertColors).find(c => k.includes(c)) || 'Normal';
    alertDist[k] = v;
  });
  renderBars('alert-bars', alertDist, Object.values(alertColors));

  // Attack chain table
  renderChainTable('chain-table', resData.chain_table || []);

  // Top processes
  renderProcs('top-procs', resData.top_processes || {});

  // Report
  renderMarkdown('report-body', resData.report || 'No report generated.');

  // Download button
  document.getElementById('dl-report-btn').onclick = () => {
    window.location.href = '/api/report/download/' + jobId;
  };

  showScreen('results');
}

// ── Render helpers ────────────────────────────────────────────────────────────
function renderBars(elId, data, colors) {
  const el = document.getElementById(elId);
  if (!data || !Object.keys(data).length) { el.innerHTML = '<div style="color:var(--text-dim);font-size:12px;">No data</div>'; return; }
  const max = Math.max(...Object.values(data));
  el.innerHTML = Object.entries(data).sort((a,b) => b[1]-a[1]).map(([k, v], i) => `
    <div class="bar-row">
      <div class="bar-name" title="${escHtml(k)}">${escHtml(k)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.round(v/max*100)}%;background:${colors[i % colors.length]};"></div></div>
      <div class="bar-count">${fmt(v)}</div>
    </div>`).join('');
}

function renderChainTable(elId, chains) {
  const el = document.getElementById(elId);
  if (!chains.length) { el.innerHTML = '<div style="color:var(--text-dim);font-size:12px;">No chains found.</div>'; return; }
  el.innerHTML = `<table>
    <thead><tr>
      <th>Chain</th><th>Events</th><th>Max Risk</th><th>Tactics</th>
    </tr></thead>
    <tbody>
    ${chains.map(c => {
      const risk = (c.MaxRiskScore || 0);
      const riskCls = risk >= 70 ? 'risk-high' : risk >= 40 ? 'risk-med' : 'risk-low';
      const tactics = (c.Tactics || []).map(t => `<span class="tactic-pill">${escHtml(t)}</span>`).join('');
      return `<tr>
        <td><span class="chain-id">#${c.AttackChainID}</span></td>
        <td>${c.EventCount}</td>
        <td><span class="risk-badge ${riskCls}">${Math.round(risk)}</span></td>
        <td><div class="tactic-pills">${tactics || '<span style="color:var(--text-dim)">—</span>'}</div></td>
      </tr>`;
    }).join('')}
    </tbody>
  </table>`;
}

function renderProcs(elId, procs) {
  const el = document.getElementById(elId);
  const entries = Object.entries(procs).sort((a,b) => b[1]-a[1]);
  if (!entries.length) { el.innerHTML = '<div style="color:var(--text-dim);font-size:12px;">No data.</div>'; return; }
  el.innerHTML = entries.map(([name, count]) => `
    <div class="proc-row">
      <div class="proc-name">${escHtml(name)}</div>
      <div class="proc-count">${fmt(count)}</div>
    </div>`).join('');
}

function renderMarkdown(elId, md) {
  const el = document.getElementById(elId);
  // Very lightweight markdown: headings, bold, lists
  let html = escHtml(md)
    .replace(/^#{1} (.+)$/gm, '<h1>$1</h1>')
    .replace(/^#{2} (.+)$/gm, '<h2>$1</h2>')
    .replace(/^#{3} (.+)$/gm, '<h2>$1</h2>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/^(?!<[hulo])/gm, '');
  el.innerHTML = '<p>' + html + '</p>';
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val ?? '—';
}

function fmt(n) {
  if (n == null) return '—';
  return Number(n).toLocaleString();
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
