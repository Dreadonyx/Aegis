const $ = selector => document.querySelector(selector);
// Telemetry is attacker-controlled: show control, bidirectional, and zero-width characters as visible escapes.
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
const visible = value => String(value ?? '').replace(CONTROL, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
const esc = value => visible(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const statusLabel = s => ({false_positive: 'False positive'})[s] || s[0].toUpperCase() + s.slice(1);
const fmtTime = t => new Date(t).toISOString().slice(11, 19);
const fmtDate = t => new Date(t).toISOString().slice(0, 10);
const names = {
  'cowrie.session.connect': 'Session connected', 'cowrie.login.failed': 'Authentication failed',
  'cowrie.login.success': 'Honeypot login accepted', 'cowrie.command.input': 'Shell input observed',
  'cowrie.session.file_download': 'File download recorded', 'cowrie.session.closed': 'Session closed',
  'cowrie.session.file_upload': 'File upload recorded', 'suricata.alert': 'IDS alert (Suricata)',
  'cowrie.client.version': 'Client version sent', 'cowrie.client.kex': 'Key exchange offered', 'cowrie.client.fingerprint': 'Public key offered',
  'cowrie.session.params': 'Session parameters', 'cowrie.command.success': 'Command ran', 'cowrie.command.failed': 'Command failed',
  'cowrie.log.closed': 'Session recording closed', 'cowrie.direct-tcpip.request': 'Port-forward request', 'cowrie.session.file_download.failed': 'File download failed'
};
const titles = {
  incidents: ['Investigations', 'Investigation workspace', 'Turn observations into an evidence-backed incident story.'],
  events: ['Event explorer', 'Explore the evidence', 'Search observations. Open an event to inspect every retained field.'],
  rules: ['Detection rules', 'An open detection playbook', 'Understand exactly why an observation becomes a finding.'],
  findings: ['Findings', 'Every finding, with its reasons', 'Rules, sequences, statistics, and ML, each with rationale, version, and evidence.'],
  sources: ['Sources', 'Ingestion health', 'Checkpoints, lag, duplicates, and quarantined lines for every source.'],
  lab: ['Lab & validation', 'Build confidence in the pipeline', 'Replay known observations and inspect the measured outcomes.']
};
let source = 'demo', view = 'incidents', overview = null, selected = null;
let currentIncident = null, eventPage = 1, visibleEvents = [], findingPage = 1, currentEvent = null, currentSession = null;
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
    if (response.status === 401 && !path.startsWith('/api/v1/auth/')) { window.location.assign('/login'); throw new Error('Sign in to continue.'); }
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
  if (next === 'findings') loadFindings().catch(e => notify(e.message, true));
  if (next === 'sources') loadSources().catch(e => notify(e.message, true));
  if (next === 'lab') loadEvaluation().catch(e => notify(e.message, true));
}

async function whoAmI() {
  const me = await api('/api/v1/auth/me');
  $('#who').textContent = me.auth === 'off' ? 'Local mode · no sign-in' : `${me.user} · ${me.role}`;
  $('#logout').hidden = me.auth === 'off';
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
    $('#metric-rules').firstChild.nodeValue = `${data.rules.length} `;
    const byEngine = {};
    data.finding_counts.forEach(c => byEngine[c.engine] = (byEngine[c.engine] || 0) + c.count);
    $('#detection-strip').innerHTML = `<span>Active findings</span>${[['rule', 'Rules'], ['sequence', 'Sequences'], ['statistical', 'Statistics'], ['ml', 'ML']]
      .map(([k, label]) => `<button class="strip-item" data-findings-engine="${k}"><strong>${byEngine[k] || 0}</strong> ${label}</button>`).join('')}
      <span class="strip-note">${esc(data.dataset_label)}</span>`;
    $('#nav-count').textContent = data.incidents_total.toLocaleString();
    $('#incident-count').textContent = data.incidents_total.toLocaleString();
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
  $('#rule-list').innerHTML = rules.map(r => `<article class="rule-row"><div class="rule-id">${esc(r.id)}<small>${{sequence: 'Sequence', statistical: 'Statistic', ml: 'ML'}[r.engine] || 'Rule'} v${esc(r.version)}</small></div>
    <div><h3>${esc(r.name)}</h3><p>${esc(r.description)}</p><p class="rule-rationale">Severity: ${esc(r.severity_rationale)}</p>
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
    <div class="incident-meta"><span>${esc(i.src_ip)}</span><span>${esc(i.sensor)}</span>${i.sessions?.length > 1 ? `<span>${i.sessions.length} sessions</span>` : ''}</div>
    <div class="incident-bottom"><span>${i.findings.length} finding${i.findings.length === 1 ? '' : 's'}</span>
    <span class="workflow-state ${esc(i.status)}">${i.status === 'resolved' ? '✓ ' : ''}${esc(statusLabel(i.status))}</span></div></button>`).join('')
    : '<div class="empty compact"><h2>No matching incidents</h2><p>Replay the demo, import events, or adjust the filters.</p></div>';
  if (overview.incidents_truncated) $('#incident-list').insertAdjacentHTML('beforeend', `<p class="queue-note">Showing the ${overview.incidents.length.toLocaleString()} most severe and recent of ${overview.incidents_total.toLocaleString()} incidents. Filters apply to these; the Findings view and /api/v1/incidents cover the rest.</p>`);
}

function renderAnalystActivity(activity) {
  return activity.length ? activity.map(a => `<article class="analyst-entry ${esc(a.kind)}"><div>
    <strong>${{note: 'Analyst note', status: 'Status changed', merge: 'Cases merged'}[a.kind] || esc(a.kind)}${a.actor ? ` · ${esc(a.actor)}` : ''}</strong>
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
    <span class="muted">${esc(statusLabel(incident.status))}</span><span class="case-id">Case ${esc(id.slice(0, 8))}</span></div>
    <h2>${esc(incident.title)}</h2><div class="detail-meta"><span>Source <strong>${esc(incident.src_ip)}</strong></span>
    <span>Sensor <strong>${esc(incident.sensor)}</strong></span><span>${fmtDate(incident.last_seen)}</span></div>
    <div class="case-summary"><span><strong>${incident.events.length}</strong> related events</span>${incident.sessions?.length > 1 ? `<span><strong>${incident.sessions.length}</strong> sessions</span>` : ''}<span><strong>${duration}s</strong> observed span</span><span>Ruleset ${esc(incident.ruleset_version)}</span></div>
    <div class="detail-actions"><select id="incident-status" aria-label="Incident workflow status">
    ${['open', 'investigating', 'resolved', 'false_positive'].map(s => `<option value="${s}" ${incident.status === s ? 'selected' : ''}>${statusLabel(s)}</option>`).join('')}</select>
    <a class="button secondary" href="/api/incidents/${id}/report?${query()}">Export report ↓</a>
    <a class="button secondary" href="/api/incidents/${id}/evidence?${query()}">Evidence JSON ↓</a>
    <button class="button secondary" id="ai-report" ${overview.ai_enabled ? '' : 'disabled'} title="${overview.ai_enabled ? 'Summarize findings with your local model' : 'Configure a local Ollama model in the setup guide'}">Generate AI draft</button></div></div>
    <div class="detail-body"><h3 class="section-label">Why this was flagged <span>${incident.findings.length} finding${incident.findings.length === 1 ? '' : 's'}</span></h3>
    ${incident.findings.map(f => `<article class="finding ${f.engine === 'sequence' ? 'sequence' : ''}"><strong>${esc(f.name)}</strong><p>${esc(f.description)}</p>
    ${f.rationale ? `<p class="finding-why"><span>Why</span>${esc(f.rationale.explanation)}</p>` : ''}
    <div class="finding-links">${f.technique ? `<a class="technique" href="https://attack.mitre.org/techniques/${esc(f.technique.replace('.', '/'))}/" target="_blank" rel="noreferrer">${esc(f.technique)} ↗</a>` : ''}
    <span class="technique">${esc(f.id)} v${esc(f.rule_version)}</span><span class="technique">${{sequence: 'Sequence', statistical: 'Statistic', ml: 'ML'}[f.engine] || 'Rule'}</span>
    <a class="evidence-link" href="#event-${esc(f.evidence_ids[0])}">${f.evidence_ids.length} evidence event${f.evidence_ids.length === 1 ? '' : 's'}</a></div>
    ${f.rationale ? `<details class="facts"><summary>Facts behind this finding</summary><pre>${esc(JSON.stringify(f.rationale.facts, null, 2))}</pre></details>` : ''}</article>`).join('')}
    ${(incident.signals || []).length ? `<h3 class="section-label">Related statistical signals <span>Unusual, not proof · not part of severity</span></h3>
    ${incident.signals.map(s => `<article class="finding signal"><strong>${esc(s.name)}</strong>
    <p class="finding-why"><span>Why</span>${esc(s.rationale.explanation)}</p>
    <div class="finding-links"><span class="technique">${esc(s.id)} ${s.engine === 'ml' ? esc(s.rule_version) : `v${esc(s.rule_version)}`}</span>
    ${s.engine === 'ml'
      ? `<span class="technique">Model score ${esc(s.score)} · above ${esc(s.rationale.facts.training_percentile)}% of training sessions (not a probability)</span>`
      : `<span class="technique">Robust z ${esc(s.score)} (unusualness, not probability)</span><span class="technique">Baseline n=${esc(s.rationale.facts.baseline?.sample_size)}</span>`}</div>
    <details class="facts"><summary>Facts behind this signal</summary><pre>${esc(JSON.stringify(s.rationale.facts, null, 2))}</pre></details></article>`).join('')}` : ''}
    ${(incident.correlation || []).filter(c => c.strength === 'weak').map(c => `<p class="correlation-note"><strong>Weak link.</strong> ${esc(c.explanation)}</p>`).join('')}
    <div id="ai-output"></div><h3 class="section-label timeline-title">Evidence timeline <span>${incident.events.length} related events</span></h3>
    <div class="timeline">${incident.events.map(e => `<article class="timeline-event" id="event-${e.id}"><time datetime="${esc(e.timestamp)}" title="${esc(e.timestamp)}">${fmtTime(e.timestamp)}</time><div>
      <button class="event-link" data-event="${e.id}">${esc(names[e.eventid] || e.eventid)}</button>
      ${e.input || e.url || e.username || e.signature ? `<code>${esc(e.input || e.url || (e.username ? `User: ${e.username}` : `Signature ${e.signature_id}: ${e.signature}`))}</code>` : ''}
      <span class="evidence-id">${esc(e.id)} · <button class="session-link" data-session="${esc(e.session)}" data-sensor="${esc(e.sensor)}">${esc(e.session)}</button>${e.link === 'source_address' ? ' <span class="link-tag">other session · address-linked</span>' : e.link === 'finding_session' ? ' <span class="link-tag">other session</span>' : ''}</span></div></article>`).join('')}</div>
    <section class="analyst-section"><h3 class="section-label">Analyst notebook <span>Saved with this incident</span></h3>
      <form id="note-form"><label for="note-text">Investigation note</label><textarea id="note-text" rows="3" maxlength="2000" required placeholder="What did you check? What explains this activity?">${esc(drafts.get(id) || '')}</textarea>
      <div class="note-actions"><small id="note-hint">${drafts.get(id) ? 'Unsaved draft' : 'Up to 2,000 characters. Notes are append-only.'}</small><button class="button primary" type="submit">Save note</button></div></form>
      <div id="analyst-activity">${renderAnalystActivity(incident.activity)}</div></section>
    <div class="report-note">${source === 'demo' ? 'Synthetic demo observations, not observed attacks. ' : ''}Findings come from deterministic rules and sequences. Address-linked sessions may belong to different clients. Review session context before escalating.</div></div>`;
  if (aiDrafts.has(id)) renderAI(aiDrafts.get(id));
}

function renderAI(result) {
  const v = result.validation;
  $('#ai-output').innerHTML = `<section class="ai-draft"><h3></h3>${v ? `<p class="ai-check ${esc(v.verdict)}"><strong>${esc(v.verdict.replace('_', ' '))}</strong> · ${esc(v.explanation)}
    ${v.cited_valid} valid citation${v.cited_valid === 1 ? '' : 's'}${v.cited_invalid.length ? ` · invented IDs: ${v.cited_invalid.map(esc).join(', ')}` : ''}${v.uncited_statements ? ` · ${v.uncited_statements} uncited statement${v.uncited_statements === 1 ? '' : 's'}` : ''}</p>` : ''}<pre></pre></section>`;
  $('#ai-output h3').textContent = result.label; $('#ai-output pre').textContent = visible(result.text);
}

function eventFilters() {
  const params = new URLSearchParams({source});
  const q = $('#event-search').value; if (q) params.set('q', q);
  [['filter-type', 'event_type'], ['filter-session', 'session'], ['filter-sensor', 'sensor'], ['filter-src', 'src_ip']]
    .forEach(([id, key]) => { const v = $(`#${id}`).value.trim(); if (v) params.set(key, v); });
  // datetime-local has no zone; the workspace is UTC throughout.
  [['filter-since', 'since'], ['filter-until', 'until']].forEach(([id, key]) => { const v = $(`#${id}`).value; if (v) params.set(key, `${v}Z`); });
  return params.toString();
}

async function loadEvents() {
  const version = ++eventVersion;
  const filters = eventFilters();
  $('#export-csv').href = `/api/v1/events/export.csv?${filters}`;
  const data = await api(`/api/events?${filters}&page=${eventPage}&limit=${$('#page-size').value}`);
  if (version !== eventVersion) return;
  if (eventPage > data.pages) { eventPage = data.pages; return loadEvents(); }
  visibleEvents = data.events;
  $('#event-count').textContent = `${data.total.toLocaleString()} matching events · click an event for full evidence`;
  $('#page-info').textContent = `Page ${data.page} of ${data.pages}`;
  $('#prev-page').disabled = data.page <= 1; $('#next-page').disabled = data.page >= data.pages;
  $('#event-rows').innerHTML = data.events.length ? data.events.map(e => `<tr><td>${fmtTime(e.timestamp)}<small>${fmtDate(e.timestamp)}</small></td>
    <td>${esc(e.src_ip)}<small><button class="session-link" data-session="${esc(e.session)}" data-sensor="${esc(e.sensor)}">${esc(e.session)}</button></small></td><td><button class="event-link" data-event="${e.id}">${esc(names[e.eventid] || e.eventid)}</button><small>${esc(e.id)}</small></td>
    <td>${esc(e.input || e.url || e.username || e.signature || '—')}</td></tr>`).join('') : '<tr><td colspan="4" class="table-empty">No matching events. Adjust your search, import telemetry, or replay the demo.</td></tr>';
}

async function loadEvaluation() {
  const r = await api('/api/evaluation');
  $('#evaluation').innerHTML = `<div class="evaluation-grid">${[['True positives', r.sessions.true_positives], ['False positives', r.sessions.false_positives], ['False negatives', r.sessions.false_negatives], ['True negatives', r.sessions.true_negatives]]
    .map(([label, n]) => `<div><strong>${n}</strong>${label}</div>`).join('')}</div><p>${esc(r.scope)}</p>`;
  $('#check-summary').textContent = `${r.passed} / ${r.total} passed`;
  const st = await api(`/api/v1/statistics?${query()}`);
  const metricNames = {'STAT-001': 'Sensor event rate', 'STAT-002': 'Username breadth per source', 'STAT-003': 'Commands per session', 'STAT-004': 'Session duration'};
  $('#stats-status').textContent = !st.enabled ? 'Disabled by configuration' : st.dirty ? `Recompute pending: ${st.last_error || 'error'}`
    : `${st.signals} signal${st.signals === 1 ? '' : 's'} · ${st.cold_start ? 'cold start (some baselines insufficient)' : 'baselines established'}`;
  $('#baseline-summary').classList.toggle('pending', !st.baselines.length || st.cold_start);
  $('#baseline-summary').textContent = st.baselines.length ? `${st.baselines.filter(b => b.state === 'established').length} / ${st.baselines.length} established` : 'No data';
  $('#baseline-results').innerHTML = st.baselines.map(b => `<div class="check-row"><span class="check-icon ${b.state === 'established' ? 'pass' : 'wait'}">${b.state === 'established' ? '✓' : '…'}</span>
    <span>${esc(metricNames[b.metric] || b.metric)}${b.entity.sensor ? ` · ${esc(b.entity.sensor)}` : ''}</span>
    <span>${b.state === 'established' ? 'Established' : 'Insufficient'} · ${b.sample_size} / ${b.required}${b.drift?.change_ratio ? ` · drift ×${esc(b.drift.change_ratio)}` : ''}</span></div>`).join('')
    || '<p class="muted">No observations in this dataset yet.</p>';
  const m = await api(`/api/v1/ml?${query()}`);
  $('#ml-status').textContent = !m.enabled ? 'Off (default) · enable only after evaluating a model'
    : m.dirty ? `Recompute pending: ${m.last_error || 'error'}`
    : m.status === 'ok' ? `${m.model.model_version} · ${m.scored_sessions} sessions scored · ${m.signals} signal${m.signals === 1 ? '' : 's'}`
    : `No ML output (${m.status}): ${m.detail || ''}`;
  const chain = await api('/api/v1/evidence/verify');
  $('#chain-status').textContent = chain.valid
    ? `Verified · ${chain.records.toLocaleString()} raw records${chain.purged ? ` (${chain.purged} purged by retention)` : ''}${chain.head_hash ? ` · head ${chain.head_hash.slice(0, 12)}…` : ''}`
    : `Integrity failure at record ${chain.first_invalid_seq}: ${chain.reason}`;
  $('#check-results').innerHTML = r.checks.map(c => `<div class="check-row"><span class="check-icon ${c.passed ? 'pass' : 'fail'}">${c.passed ? '✓' : '×'}</span><span>${esc(c.name)}</span><span>${c.passed ? 'Passed' : 'Failed'}</span></div>`).join('');
}

async function openEvent(record) {
  currentEvent = record;
  $('#event-json').textContent = visible(JSON.stringify(record, null, 2));
  $('#event-original').hidden = true; $('#event-original').textContent = '';
  $('#event-provenance').innerHTML = '<p class="muted">Loading provenance…</p>';
  $('#event-dialog').showModal();
  try {
    const p = await api(`/api/v1/events/${encodeURIComponent(record.id)}/provenance?${query()}`);
    if (currentEvent !== record) return;
    currentEvent.original = p.original;
    $('#show-original').disabled = !p.original;
    $('#event-provenance').innerHTML = `<h3 class="section-label">Provenance <span>${esc(p.dataset_label)}</span></h3>` + (p.provenance.length
      ? p.provenance.map(r => `<dl class="provenance"><dt>Mode</dt><dd>${esc(r.ingestion_mode)} · ${esc(r.source_id)} (${esc(r.source_type)})</dd>
          <dt>Located at</dt><dd>${esc(r.locator || '—')} in ${esc(r.file_id || '—')}</dd><dt>Ingested</dt><dd>${esc(r.ingested_at)}</dd>
          <dt>Parser</dt><dd>${esc(r.parser_version)} · schema ${esc(r.schema_version)}</dd><dt>Raw SHA-256</dt><dd class="mono">${esc(r.raw_sha256)}</dd>
          <dt>Chain record</dt><dd>#${esc(r.seq)} · ${esc(r.chain_hash.slice(0, 16))}…</dd></dl>`).join('')
      : '<p class="muted">Stored before raw evidence retention (schema 1); no original record exists.</p>');
  } catch (error) { $('#event-provenance').innerHTML = `<p class="muted">${esc(error.message)}</p>`; }
}

async function openSession(session, sensor) {
  currentSession = {session, sensor};
  $('#session-title').textContent = `Session ${visible(session)}`;
  $('#session-body').innerHTML = '<p class="muted">Loading session…</p>';
  if (!$('#session-dialog').open) $('#session-dialog').showModal();
  const t = await api(`/api/v1/sessions/${encodeURIComponent(session)}/timeline?${query()}${sensor ? `&sensor=${encodeURIComponent(sensor)}` : ''}`);
  const label = t.label, hint = t.suggestion;
  const typeNames = {credential_access: 'Credential access', discovery: 'Discovery', transfer: 'Transfer', intrusion_sequence: 'Intrusion sequence', anomaly: 'Anomaly'};
  const first = t.events[0], last = t.events[t.events.length - 1];
  $('#session-body').innerHTML = `<div class="session-meta"><span>Source <strong>${esc(first.src_ip)}</strong></span><span>Sensor <strong>${esc(first.sensor)}</strong></span>
      <span><strong>${t.events.length}</strong> events${t.truncated ? ' (first 2,000)' : ''}</span><span>${fmtDate(first.timestamp)} ${fmtTime(first.timestamp)}–${fmtTime(last.timestamp)} UTC</span></div>
    ${t.ambiguous ? '<p class="correlation-note">This session ID appears on several sensors. Open it from an event to choose one before labeling.</p>' : `
    <section class="label-box"><h3 class="section-label">Analyst label <span>${label ? `${esc(label.label)} · ${esc(label.actor)} · ${fmtDate(label.labeled_at)}` : 'Not labeled'}</span></h3>
      ${hint ? `<p class="label-hint"><strong>Suggested: ${esc(hint.label)}</strong>${hint.types.length ? ` (${hint.types.map(x => esc(typeNames[x])).join(', ')})` : ''}. ${esc(hint.basis)}</p>` : '<p class="label-hint">No suggestion: this session needs a human decision.</p>'}
      <form id="label-form"><div class="label-choice">${['malicious', 'benign'].map(v => `<label><input type="radio" name="label" value="${v}" ${label?.label === v ? 'checked' : ''}> ${v === 'malicious' ? 'Malicious (alert-worthy)' : 'Benign (should stay quiet)'}</label>`).join('')}</div>
        <div class="label-types">${Object.entries(typeNames).map(([k, n]) => `<label><input type="checkbox" name="types" value="${k}" ${label?.types.includes(k) ? 'checked' : ''}> ${n}</label>`).join('')}</div>
        <input name="note" maxlength="500" placeholder="Why? (optional)" value="${esc(label?.note || '')}">
        <div class="note-actions"><button class="text-button" type="button" id="clear-label" ${label ? '' : 'disabled'}>Clear label</button><button class="button primary" type="submit">Save label</button></div>
        <p id="label-saved" class="label-saved ${label ? 'is-saved' : ''}" role="status">${label ? `✓ Saved as <strong>${esc(label.label)}</strong>${label.types.length ? ` (${label.types.map(x => esc(typeNames[x])).join(', ')})` : ''} at ${fmtTime(label.labeled_at)} UTC by ${esc(label.actor)}` : 'Not saved yet.'}</p></form>
      ${t.label_history.length ? `<details class="facts"><summary>Label history (${t.label_history.length})</summary><ul class="history">${t.label_history.map(h => `<li>${fmtDate(h.changed_at)} ${fmtTime(h.changed_at)} · ${esc(h.actor)}: ${esc(h.before?.label || 'none')} → ${esc(h.after?.label || 'none')}</li>`).join('')}</ul></details>` : ''}
    </section>`}
    ${t.findings.length ? `<h3 class="section-label">Linked findings <span>${t.findings.length}</span></h3>${t.findings.map(f => `<div class="finding-row">${severityPill(f.severity)} <strong>${esc(f.name)}</strong> <span class="technique">${esc(f.id)}</span>${f.incident_id ? ` <button class="text-button" data-open-incident="${esc(f.incident_id)}">Open incident</button>` : ''}</div>`).join('')}` : ''}
    <h3 class="section-label timeline-title">Timeline <span>event order, UTC</span></h3>
    <div class="timeline">${t.events.map(e => `<article class="timeline-event"><time datetime="${esc(e.timestamp)}">${fmtTime(e.timestamp)}</time><div>
      <button class="event-link" data-event="${esc(e.id)}">${esc(names[e.eventid] || e.eventid)}</button>
      ${e.input || e.url || e.username || e.client_version || e.signature ? `<code>${esc(e.input || e.url || (e.username ? `User: ${e.username}` : e.signature ? `Signature ${e.signature_id}: ${e.signature}` : e.client_version))}</code>` : ''}
      <span class="evidence-id">${esc(e.id)}</span></div></article>`).join('')}</div>`;
  visibleEvents = [...visibleEvents.filter(v => !t.events.some(e => e.id === v.id)), ...t.events];
  currentSession.saved = label ? {label: label.label, types: [...label.types].sort(), note: label.note || ''} : null;
  updateLabelButton();
}

function labelFormValue() {
  const form = $('#label-form');
  return {label: form.querySelector('input[name="label"]:checked')?.value || null,
          types: [...form.querySelectorAll('input[name="types"]:checked')].map(i => i.value).sort(), note: form.note.value.trim()};
}

// Saved and unchanged: nothing to save. Any edit turns the button back on and says so.
function updateLabelButton() {
  const form = $('#label-form');
  if (!form || !currentSession) return;
  const saved = currentSession.saved, now = labelFormValue();
  const unchanged = saved && JSON.stringify(saved) === JSON.stringify(now);
  const button = form.querySelector('button[type="submit"]'), status = $('#label-saved');
  button.disabled = Boolean(unchanged);
  button.textContent = unchanged ? 'Saved ✓' : saved ? 'Save changes' : 'Save label';
  if (saved && !unchanged) {
    status.className = 'label-saved is-dirty';
    status.textContent = `Unsaved changes. Currently saved as ${saved.label}; click "Save changes" to update it.`;
  } else if (saved) {
    status.className = 'label-saved is-saved';
  }
}

async function saveLabel(clear = false) {
  const form = $('#label-form');
  const label = clear ? null : form.querySelector('input[name="label"]:checked')?.value;
  if (!clear && !label) throw new Error('Choose malicious or benign first.');
  const saved = currentSession.saved;
  if (clear && saved && !confirm(`Clear the saved "${saved.label}" label for this session?`)) return;
  if (!clear && saved && saved.label !== label && !confirm(`This session is saved as ${saved.label}. Change it to ${label}?`)) return;
  const types = [...form.querySelectorAll('input[name="types"]:checked')].map(i => i.value);
  const {session, sensor} = currentSession;
  await api(`/api/v1/sessions/${encodeURIComponent(session)}/label?${query()}${sensor ? `&sensor=${encodeURIComponent(sensor)}` : ''}`,
    {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({label, types, note: form.note.value || null})});
  notify(clear ? 'Label cleared.' : 'Session label saved.');
  await openSession(session, sensor);
}

async function loadFindings() {
  const params = new URLSearchParams({source, page: findingPage, limit: 25, status: $('#finding-status').value});
  if ($('#finding-engine').value) params.set('engine', $('#finding-engine').value);
  const data = await api(`/api/v1/findings?${params}`);
  if (findingPage > data.pages) { findingPage = data.pages; return loadFindings(); }
  $('#finding-count').textContent = `${data.total.toLocaleString()} ${$('#finding-status').value} finding${data.total === 1 ? '' : 's'}`;
  $('#finding-page-info').textContent = `Page ${data.page} of ${data.pages}`;
  $('#finding-prev').disabled = data.page <= 1; $('#finding-next').disabled = data.page >= data.pages;
  const scoreText = f => f.score_type === 'robust_z' ? `Robust z ${esc(f.score)} (unusualness, not probability)`
    : f.score_type === 'isolation_forest_anomaly' ? `Model score ${esc(f.score)} · above ${esc(f.rationale.facts.training_percentile)}% of training sessions` : '';
  $('#finding-list').innerHTML = data.findings.length ? data.findings.map(f => `<article class="finding ${esc(f.engine)}"><div class="finding-top">${severityPill(f.severity)}
      <strong>${esc(f.name)}</strong><span class="incident-time">${fmtDate(f.observed_at)} ${fmtTime(f.observed_at)} UTC</span></div>
    <p class="finding-why"><span>Why</span>${esc(f.rationale.explanation)}</p>
    <div class="finding-links"><span class="technique">${esc(f.id)} ${f.engine === 'ml' ? esc(f.rule_version) : `v${esc(f.rule_version)}`}</span><span class="technique">${{sequence: 'Sequence', statistical: 'Statistic', ml: 'ML'}[f.engine] || 'Rule'}</span>
      ${scoreText(f) ? `<span class="technique">${scoreText(f)}</span>` : ''}<span class="technique">${f.evidence_ids.length} evidence event${f.evidence_ids.length === 1 ? '' : 's'}</span>
      ${f.session ? `<button class="text-button session-link" data-session="${esc(f.session)}" data-sensor="${esc(f.sensor)}">Open session</button>` : ''}
      ${f.incident_id ? `<button class="text-button" data-open-incident="${esc(f.incident_id)}">Open incident</button>` : ''}</div>
    <p class="finding-limit">${esc(f.severity_rationale)}</p>
    <details class="facts"><summary>Facts behind this finding</summary><pre>${esc(JSON.stringify(f.rationale.facts, null, 2))}</pre></details></article>`).join('')
    : '<div class="empty compact"><h2>No findings</h2><p>Nothing in this dataset meets a rule, sequence, statistic, or model threshold.</p></div>';
}

async function loadSources() {
  const data = await api('/api/v1/sources');
  const ago = s => s == null ? '—' : s < 120 ? `${Math.round(s)} s ago` : s < 7200 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
  const cards = await Promise.all(data.sources.map(async s => {
    const errors = s.malformed_total ? (await api(`/api/v1/sources/${encodeURIComponent(s.source_id)}/errors?limit=5`)).errors : [];
    const c = s.collector;
    return `<article class="panel source-card"><div class="panel-heading"><h2>${esc(s.source_id)}</h2><span class="pill ${c && c.state !== 'running' ? 'medium' : 'low'}">${esc(c ? c.state.replace('_', ' ') : s.ingestion_mode)}</span></div>
      <dl><dt>Type</dt><dd>${esc(s.source_type)} · ${esc(s.ingestion_mode)}</dd><dt>Newest event</dt><dd>${esc(s.last_event_time || '—')} (${ago(s.seconds_since_last_event)})</dd>
      <dt>Last commit</dt><dd>${esc(s.last_commit_at)}</dd><dt>Events</dt><dd>${s.events_total.toLocaleString()} new · ${s.duplicates_total.toLocaleString()} duplicates</dd>
      <dt>Quarantined</dt><dd>${s.malformed_total.toLocaleString()} lines</dd><dt>Rotations</dt><dd>${s.rotations_total} · truncations ${s.truncations_total}</dd>
      ${c ? `<dt>Collector</dt><dd>${esc(c.detail)}${c.bytes_behind != null ? ` · ${c.bytes_behind.toLocaleString()} bytes behind` : ''}${c.consecutive_failures ? ` · ${c.consecutive_failures} failures` : ''}</dd>` : ''}</dl>
      ${errors.length ? `<h3 class="section-label">Recent quarantined lines <span>metadata only</span></h3><ul class="history">${errors.map(e => `<li>${esc(e.locator)} · ${esc(e.reason)} · ${e.line_bytes} bytes</li>`).join('')}</ul>` : ''}</article>`;
  }));
  $('#source-list').innerHTML = cards.join('') || '<div class="panel empty compact"><h2>No sources yet</h2><p>Replay the demo, import a Cowrie log, or configure AEGIS_COWRIE_LOG for live collection.</p></div>';
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
    if (target.dataset.source) { source = target.dataset.source; selected = null; syncSource(); await load(); if (view === 'lab') await loadEvaluation(); }
    if (target.dataset.incident) { selected = target.dataset.incident; renderQueue(); await loadDetail(selected); }
    if (target.dataset.event) {
      const record = [...visibleEvents, ...(currentIncident?.events || [])].find(e => e.id === target.dataset.event);
      if (record) await openEvent(record);
    }
    if (target.id === 'close-event') $('#event-dialog').close();
    if (target.id === 'logout') { await api('/api/v1/auth/logout', {method: 'POST'}); window.location.assign('/login'); return; }
    if (target.id === 'close-session') $('#session-dialog').close();
    if (target.dataset.session) await openSession(target.dataset.session, target.dataset.sensor);
    if (target.id === 'open-session' && currentEvent) { $('#event-dialog').close(); await openSession(currentEvent.session, currentEvent.sensor); }
    if (target.id === 'show-original' && currentEvent?.original) { $('#event-original').textContent = visible(JSON.stringify(currentEvent.original, null, 2)); $('#event-original').hidden = false; }
    if (target.id === 'clear-label') await saveLabel(true);
    if (target.dataset.openIncident) { $('#session-dialog').close(); showView('incidents'); selected = target.dataset.openIncident; renderQueue(); await loadDetail(selected); }
    if (target.dataset.findingsEngine) { $('#finding-engine').value = target.dataset.findingsEngine; findingPage = 1; showView('findings'); }
    if (['finding-next', 'finding-prev'].includes(target.id)) { findingPage += target.id === 'finding-next' ? 1 : -1; await loadFindings(); }
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

document.addEventListener('submit', async event => {
  if (event.target.id === 'label-form') { event.preventDefault(); try { await saveLabel(); } catch (error) { notify(error.message, true); } }
  if (event.target.id === 'event-filters') { event.preventDefault(); eventPage = 1; loadEvents().catch(e => notify(e.message, true)); }
});
document.addEventListener('input', event => { if (event.target.closest('#label-form')) updateLabelButton(); });
document.addEventListener('change', event => { if (event.target.closest('#label-form')) updateLabelButton(); });
document.addEventListener('reset', event => {
  if (event.target.id === 'event-filters') setTimeout(() => { eventPage = 1; loadEvents().catch(e => notify(e.message, true)); });
});
['finding-engine', 'finding-status'].forEach(id => $(`#${id}`).addEventListener('change', () => { findingPage = 1; loadFindings().catch(e => notify(e.message, true)); }));

$('#eve-input').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  try {
    if (file.size > 2 * 1024 * 1024) throw new Error('Choose a file smaller than 2 MB.');
    const form = new FormData(); form.append('file', file);
    const result = await api('/api/v1/imports?format=suricata-eve', {method: 'POST', body: form});
    source = 'imported'; selected = null; syncSource(); await load();
    notify(`Imported ${result.inserted} Suricata alert${result.inserted === 1 ? '' : 's'}; skipped ${result.duplicates} duplicates and ${result.skipped_non_alert} non-alert EVE records. Read-only: nothing was blocked.`);
  } catch (error) { notify(error.message, true); } finally { event.target.value = ''; }
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
whoAmI().catch(() => {});
load().catch(error => notify(error.message, true));
