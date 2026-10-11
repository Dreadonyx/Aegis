const $ = selector => document.querySelector(selector);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtTime = t => new Date(t).toISOString().slice(11, 19);
const fmtDate = t => new Date(t).toISOString().slice(0, 10);
const names = {
  'cowrie.session.connect': 'Session connected', 'cowrie.login.failed': 'Authentication failed',
  'cowrie.login.success': 'Honeypot login accepted', 'cowrie.command.input': 'Shell input observed',
  'cowrie.session.file_download': 'File download recorded', 'cowrie.session.closed': 'Session closed'
};
const titles = {
  incidents: ['Investigations', 'Investigation workspace', 'Turn observations into an evidence-backed incident story.'],
  events: ['Event explorer', 'Explore the evidence', 'Search observations. Open an event to inspect every retained field.'],
  rules: ['Detection rules', 'An open detection playbook', 'Understand exactly why an observation becomes a finding.'],
  lab: ['Lab & validation', 'Build confidence in the pipeline', 'Replay known observations and inspect the measured outcomes.']
};
let source = 'demo', view = 'incidents', overview = null, selected = null;
let currentIncident = null, eventPage = 1, visibleEvents = [];
let loadVersion = 0, detailVersion = 0, eventVersion = 0, busy = false;
const drafts = new Map(), aiDrafts = new Map();
const query = () => `source=${source}`;
const severityPill = s => `<span class="pill ${esc(s)}">${esc(s[0].toUpperCase() + s.slice(1))}</span>`;

function notify(text, error = false) {
  $('#notice').hidden = false;
  $('#notice').className = error ? 'error' : '';
  $('#notice').textContent = text;
}

async function api(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60000);
  try {
    const response = await fetch(path, {...options, signal: controller.signal,
      headers: {'X-Aegis-CSRF': $('meta[name="csrf-token"]').content, ...options.headers}});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Request failed');
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('The request timed out. Check the service and try again.');
    if (error instanceof TypeError) throw new Error('Cannot reach Aegis. Check the local service and refresh.');
    throw error;
  } finally { clearTimeout(timer); }
}

function showView(next) {
  view = next;
  document.querySelectorAll('.view').forEach(el => el.hidden = el.id !== `view-${next}`);
  document.querySelectorAll('[data-view]').forEach(el => {
    el.classList.toggle('active', el.dataset.view === next);
    if (el.dataset.view === next) el.setAttribute('aria-current', 'page');
    else el.removeAttribute('aria-current');
  });
  const [crumb, title, sub] = titles[next];
  $('#breadcrumb').textContent = crumb; $('#page-title').textContent = title; $('#page-subtitle').textContent = sub;
  if (next === 'events') loadEvents().catch(e => notify(e.message, true));
  if (next === 'lab') loadEvaluation().catch(e => notify(e.message, true));
}

async function load({background = false} = {}) {
  const version = ++loadVersion;
  $('#refresh').setAttribute('aria-busy', 'true');
  try {
    const data = await api(`/api/overview?${query()}`);
    if (version !== loadVersion) return;
    overview = data;
    $('#metric-events').textContent = data.events.toLocaleString();
    $('#metric-open').textContent = data.open_incidents;
    $('#metric-sources').textContent = data.sources;
    $('#nav-count').textContent = data.incidents.length;
    $('#incident-count').textContent = data.incidents.length;
    $('#collector-status').textContent = data.collector;
    $('#storage-status').textContent = `${data.storage.events.toLocaleString()} / ${data.storage.limit.toLocaleString()} events across all datasets`;
    $('#ai-status').textContent = data.ai_enabled ? 'Local model configured; drafts require review' : 'Not configured · rule-based reports available';
    $('#sync-status').textContent = `Updated ${fmtTime(new Date())} UTC`;
    renderActivity(data.timeline); renderRules(data.rules);
    if (!data.incidents.some(i => i.id === selected)) selected = data.incidents[0]?.id || null;
    renderQueue();
    // Preserve the open investigation during background polling.
    if (selected && (!background || currentIncident?.id !== selected)) await loadDetail(selected);
    else if (!selected) {
      currentIncident = null;
      $('#incident-detail').innerHTML = `<div class="empty"><span class="empty-symbol">◈</span>
        <h2>${source === 'demo' ? 'Your first investigation starts here' : 'No incidents in this dataset'}</h2>
        <p>${{demo: 'Replay the synthetic demo to explore detections and their evidence.',
              imported: 'Import a Cowrie log. Observations that do not meet a rule remain in the event explorer.',
              live: 'No live observation has met a rule. Collector state is shown under Lab & validation; other observations remain in the event explorer.'}[source]}</p>
        ${source === 'demo' ? '<button class="button primary" id="empty-replay">Replay demo</button>' : ''}</div>`;
    }
    if (view === 'events' && !background) await loadEvents();
  } finally { if (version === loadVersion) $('#refresh').removeAttribute('aria-busy'); }
}

function renderActivity(timeline) {
  $('#activity').replaceChildren();
  const max = Math.max(1, ...timeline.map(v => v.count));
  for (const bin of timeline) {
    const bar = document.createElement('div'); bar.className = 'bar';
    bar.style.height = `${Math.max(3, bin.count / max * 36)}px`;
    bar.title = `${bin.time.replace('T', ' ')} UTC: ${bin.count} events`;
    $('#activity').append(bar);
  }
  $('#activity-label').textContent = timeline.length ? `${timeline[0].time.replace('T', ' ')} UTC` : 'No observations yet';
}

function renderRules(rules) {
  $('#rule-list').innerHTML = rules.map(r => `<article class="rule-row"><div class="rule-id">${esc(r.id)}</div>
    <div><h3>${esc(r.name)}</h3><p>${esc(r.description)}</p>
    ${r.technique ? `<a class="technique" href="https://attack.mitre.org/techniques/${esc(r.technique.replace('.', '/'))}/" target="_blank" rel="noreferrer">${esc(r.technique)} ↗</a>` : ''}
    </div>${severityPill(r.severity)}</article>`).join('');
}

function renderQueue() {
  if (!overview) return;
  const q = $('#incident-search').value.toLowerCase(), severity = $('#severity').value, status = $('#workflow-filter').value;
  const list = overview.incidents.filter(i => (severity === 'all' || i.severity === severity)
    && (status === 'all' || i.status === status) && JSON.stringify(i).toLowerCase().includes(q));
  $('#incident-list').innerHTML = list.length ? list.map(i => `<button class="incident-item ${i.id === selected ? 'selected' : ''}"
    data-incident="${i.id}" aria-pressed="${i.id === selected}"><div class="incident-top">${severityPill(i.severity)}
    <span class="incident-time">${fmtTime(i.last_seen)} UTC</span></div><h3>${esc(i.title)}</h3>
    <div class="incident-meta"><span>${esc(i.src_ip)}</span><span>${esc(i.sensor)}</span></div>
    <div class="incident-bottom"><span>${i.findings.length} finding${i.findings.length === 1 ? '' : 's'}</span>
    <span class="workflow-state ${esc(i.status)}">${i.status === 'resolved' ? '✓ ' : ''}${esc(i.status)}</span></div></button>`).join('')
    : '<div class="empty compact"><h2>No matching incidents</h2><p>Replay the demo, import events, or adjust the filters.</p></div>';
}

function renderAnalystActivity(activity) {
  return activity.length ? activity.map(a => `<article class="analyst-entry ${esc(a.kind)}"><div>
    <strong>${a.kind === 'note' ? 'Analyst note' : 'Status changed'}</strong>
    <time datetime="${esc(a.timestamp)}">${fmtDate(a.timestamp)} ${fmtTime(a.timestamp)} UTC</time></div><p>${esc(a.body)}</p></article>`).join('')
    : '<p class="muted activity-empty">No notes or status changes yet. Record what you checked and why.</p>';
}

async function loadDetail(id) {
  const version = ++detailVersion;
  const incident = await api(`/api/incidents/${id}?${query()}`);
  if (version !== detailVersion || id !== selected) return;
  currentIncident = incident;
  const duration = Math.max(0, Math.round((new Date(incident.last_seen) - new Date(incident.first_seen)) / 1000));
  $('#incident-detail').innerHTML = `<div class="detail-heading"><div class="eyeline">${severityPill(incident.severity)}
    <span class="muted">${esc(incident.status)}</span><span class="case-id">Case ${esc(id.slice(0, 8))}</span></div>
    <h2>${esc(incident.title)}</h2><div class="detail-meta"><span>Source <strong>${esc(incident.src_ip)}</strong></span>
    <span>Sensor <strong>${esc(incident.sensor)}</strong></span><span>${fmtDate(incident.last_seen)}</span></div>
    <div class="case-summary"><span><strong>${incident.events.length}</strong> related events</span><span><strong>${duration}s</strong> observed span</span><span>Ruleset ${esc(incident.ruleset_version)}</span></div>
    <div class="detail-actions"><select id="incident-status" aria-label="Incident workflow status">
    ${['open', 'investigating', 'resolved'].map(s => `<option value="${s}" ${incident.status === s ? 'selected' : ''}>${s[0].toUpperCase() + s.slice(1)}</option>`).join('')}</select>
    <a class="button secondary" href="/api/incidents/${id}/report?${query()}">Export report ↓</a>
    <a class="button secondary" href="/api/incidents/${id}/evidence?${query()}">Evidence JSON ↓</a>
    <button class="button secondary" id="ai-report" ${overview.ai_enabled ? '' : 'disabled'} title="${overview.ai_enabled ? 'Summarize findings with your local model' : 'Configure a local Ollama model in the setup guide'}">Generate AI draft</button></div></div>
    <div class="detail-body"><h3 class="section-label">Why this was flagged <span>${incident.findings.length} finding${incident.findings.length === 1 ? '' : 's'}</span></h3>
    ${incident.findings.map(f => `<article class="finding"><strong>${esc(f.name)}</strong><p>${esc(f.description)}</p>
    <div class="finding-links">${f.technique ? `<a class="technique" href="https://attack.mitre.org/techniques/${esc(f.technique.replace('.', '/'))}/" target="_blank" rel="noreferrer">${esc(f.technique)} ↗</a>` : ''}
    <span class="technique">${esc(f.id)}</span><a class="evidence-link" href="#event-${f.evidence_ids[0]}">${f.evidence_ids.length} evidence event${f.evidence_ids.length === 1 ? '' : 's'}</a></div></article>`).join('')}
    <div id="ai-output"></div><h3 class="section-label timeline-title">Evidence timeline <span>${incident.events.length} related events</span></h3>
    <div class="timeline">${incident.events.map(e => `<article class="timeline-event" id="event-${e.id}"><time datetime="${esc(e.timestamp)}" title="${esc(e.timestamp)}">${fmtTime(e.timestamp)}</time><div>
      <button class="event-link" data-event="${e.id}">${esc(names[e.eventid] || e.eventid)}</button>
      ${e.input || e.url || e.username ? `<code>${esc(e.input || e.url || `User: ${e.username}`)}</code>` : ''}
      <span class="evidence-id">${esc(e.id)} · ${esc(e.session)}</span></div></article>`).join('')}</div>
    <section class="analyst-section"><h3 class="section-label">Analyst notebook <span>Saved with this incident</span></h3>
      <form id="note-form"><label for="note-text">Investigation note</label><textarea id="note-text" rows="3" maxlength="2000" required placeholder="What did you check? What explains this activity?">${esc(drafts.get(id) || '')}</textarea>
      <div class="note-actions"><small id="note-hint">${drafts.get(id) ? 'Unsaved draft' : 'Up to 2,000 characters. Notes are append-only.'}</small><button class="button primary" type="submit">Save note</button></div></form>
      <div id="analyst-activity">${renderAnalystActivity(incident.activity)}</div></section>
    <div class="report-note">${source === 'demo' ? 'Synthetic demo observations. ' : ''}Findings come from deterministic rules. Review session context before escalating.</div></div>`;
  if (aiDrafts.has(id)) renderAI(aiDrafts.get(id));
}

function renderAI(result) {
  $('#ai-output').innerHTML = '<section class="ai-draft"><h3></h3><pre></pre></section>';
  $('#ai-output h3').textContent = result.label; $('#ai-output pre').textContent = result.text;
}

async function loadEvents() {
  const version = ++eventVersion;
  const data = await api(`/api/events?${query()}&page=${eventPage}&limit=${$('#page-size').value}&q=${encodeURIComponent($('#event-search').value)}`);
  if (version !== eventVersion) return;
  if (eventPage > data.pages) { eventPage = data.pages; return loadEvents(); }
  visibleEvents = data.events;
  $('#event-count').textContent = `${data.total.toLocaleString()} matching events · click an event for full evidence`;
  $('#page-info').textContent = `Page ${data.page} of ${data.pages}`;
  $('#prev-page').disabled = data.page <= 1; $('#next-page').disabled = data.page >= data.pages;
  $('#event-rows').innerHTML = data.events.length ? data.events.map(e => `<tr><td>${fmtTime(e.timestamp)}<small>${fmtDate(e.timestamp)}</small></td>
    <td>${esc(e.src_ip)}<small>${esc(e.session)}</small></td><td><button class="event-link" data-event="${e.id}">${esc(names[e.eventid] || e.eventid)}</button><small>${esc(e.id)}</small></td>
    <td>${esc(e.input || e.url || e.username || '—')}</td></tr>`).join('') : '<tr><td colspan="4" class="table-empty">No matching events. Adjust your search, import telemetry, or replay the demo.</td></tr>';
}

async function loadEvaluation() {
  const r = await api('/api/evaluation');
  $('#evaluation').innerHTML = `<div class="evaluation-grid">${[['True positives', r.sessions.true_positives], ['False positives', r.sessions.false_positives], ['False negatives', r.sessions.false_negatives], ['True negatives', r.sessions.true_negatives]]
    .map(([label, n]) => `<div><strong>${n}</strong>${label}</div>`).join('')}</div><p>${esc(r.scope)}</p>`;
  $('#check-summary').textContent = `${r.passed} / ${r.total} passed`;
  const chain = await api('/api/v1/evidence/verify');
  $('#chain-status').textContent = chain.valid
    ? `Verified · ${chain.records.toLocaleString()} raw records${chain.purged ? ` (${chain.purged} purged by retention)` : ''}${chain.head_hash ? ` · head ${chain.head_hash.slice(0, 12)}…` : ''}`
    : `Integrity failure at record ${chain.first_invalid_seq}: ${chain.reason}`;
  $('#check-results').innerHTML = r.checks.map(c => `<div class="check-row"><span class="check-icon ${c.passed ? 'pass' : 'fail'}">${c.passed ? '✓' : '×'}</span><span>${esc(c.name)}</span><span>${c.passed ? 'Passed' : 'Failed'}</span></div>`).join('');
}

function syncSource() {
  ++detailVersion; ++eventVersion; eventPage = 1; currentIncident = null;
  $('#notice').hidden = true;
  document.querySelectorAll('[data-source]').forEach(b => {
    b.classList.toggle('selected', b.dataset.source === source);
    b.setAttribute('aria-pressed', String(b.dataset.source === source));
  });
  $('#dataset-note').textContent = {
    demo: 'Synthetic observations. No attacks are executed.',
    imported: 'Uploaded historical Cowrie observations. Separate from demo and live data.',
    live: 'Observations collected from the configured Cowrie sensor. Separate from uploads and demo data.'
  }[source];
}

async function replay() {
  if (busy) return;
  busy = true;
  const buttons = [$('#replay'), $('#validate')]; buttons.forEach(b => b.disabled = true);
  try {
    const result = await api('/api/replay', {method: 'POST'});
    source = 'demo'; selected = null; syncSource(); await load(); await loadEvaluation();
    notify(`Replay complete: ${result.inserted} new events, ${result.duplicates} duplicates skipped. No network activity was generated.`);
  } finally { busy = false; buttons.forEach(b => b.disabled = false); }
}

// Delegated controls also cover incident details inserted after navigation.
document.addEventListener('click', async event => {
  const target = event.target.closest('button');
  if (!target) return;
  try {
    if (target.dataset.view) showView(target.dataset.view);
    if (target.dataset.source) { source = target.dataset.source; selected = null; syncSource(); await load(); }
    if (target.dataset.incident) { selected = target.dataset.incident; renderQueue(); await loadDetail(selected); }
    if (target.dataset.event) {
      const record = [...visibleEvents, ...(currentIncident?.events || [])].find(e => e.id === target.dataset.event);
      if (record) { $('#event-json').textContent = JSON.stringify(record, null, 2); $('#event-dialog').showModal(); }
    }
    if (target.id === 'close-event') $('#event-dialog').close();
    if (['replay', 'empty-replay', 'validate'].includes(target.id)) await replay();
    if (target.id === 'refresh') await load();
    if (['next-page', 'prev-page'].includes(target.id)) { eventPage += target.id === 'next-page' ? 1 : -1; await loadEvents(); }
    if (target.id === 'ai-report') {
      const id = selected; target.disabled = true; target.textContent = 'Generating…';
      try {
        const result = await api(`/api/incidents/${id}/ai?${query()}`, {method: 'POST'});
        aiDrafts.set(id, result);
        if (selected === id && $('#ai-output')) renderAI(result);
      } finally { if (document.contains(target)) { target.disabled = false; target.textContent = 'Generate AI draft'; } }
    }
  } catch (error) { notify(error.message, true); }
});

$('#file-input').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  try {
    if (file.size > 2 * 1024 * 1024) throw new Error('Choose a log smaller than 2 MB.');
    const form = new FormData(); form.append('file', file);
    const result = await api('/api/import', {method: 'POST', body: form});
    source = 'imported'; selected = null; syncSource(); await load();
    notify(`Imported ${result.inserted} event${result.inserted === 1 ? '' : 's'}. Skipped ${result.duplicates} duplicates.`);
  } catch (error) { notify(error.message, true); } finally { event.target.value = ''; }
});

document.addEventListener('change', async event => {
  if (event.target.id === 'page-size') { eventPage = 1; await loadEvents().catch(e => notify(e.message, true)); }
  if (event.target.id !== 'incident-status') return;
  const id = selected, previous = currentIncident.status;
  event.target.disabled = true;
  try {
    await api(`/api/incidents/${id}?${query()}`, {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status: event.target.value})});
    await load(); notify('Incident status saved.');
  } catch (error) { event.target.value = previous; event.target.disabled = false; notify(error.message, true); }
});

document.addEventListener('input', event => {
  if (event.target.id === 'note-text') {
    drafts.set(selected, event.target.value);
    $('#note-hint').textContent = `${event.target.value.length} / 2,000 characters · unsaved draft`;
  }
});

document.addEventListener('submit', async event => {
  if (event.target.id !== 'note-form') return;
  event.preventDefault();
  const id = selected, button = event.target.querySelector('button'); button.disabled = true;
  try {
    await api(`/api/incidents/${id}/notes?${query()}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text: $('#note-text').value})});
    drafts.delete(id);
    if (selected === id) await loadDetail(id);
    notify('Analyst note saved.');
  } catch (error) { button.disabled = false; notify(error.message, true); }
});

$('#incident-search').addEventListener('input', renderQueue);
$('#severity').addEventListener('change', renderQueue);
$('#workflow-filter').addEventListener('change', renderQueue);
let searchTimer;
$('#event-search').addEventListener('input', () => {
  clearTimeout(searchTimer); ++eventVersion;
  searchTimer = setTimeout(() => { eventPage = 1; loadEvents().catch(e => notify(e.message, true)); }, 200);
});
window.addEventListener('beforeunload', event => {
  if ([...drafts.values()].some(text => text.trim())) { event.preventDefault(); event.returnValue = ''; }
});
setInterval(() => {
  if ($('#live-refresh').checked && !document.hidden && !busy) {
    load({background: true}).catch(error => {
      $('#live-refresh').checked = false; notify(`Auto-refresh paused: ${error.message}`, true);
    });
  }
}, 15000);
load().catch(error => notify(error.message, true));
