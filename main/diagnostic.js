/* Browser probes only: no ESP DNS calls, no external test API, no copied site code. */
(function (root) {
  'use strict';
  const MAX_CASES = 500;
  const catalog = [
    {id: 'ads', name: 'Publicités', selected: true, domains: [
      'pagead2.googlesyndication.com', 'googleads.g.doubleclick.net', 'ad.doubleclick.net',
      'adservice.google.com', 'ads.pubmatic.com', 'ib.adnxs.com', 'static.criteo.net',
      'cdn.taboola.com', 'cdn.outbrain.com', 'adnxs.com', 'adsrvr.org', 'ads.yahoo.com']},
    {id: 'tracking', name: 'Traqueurs et télémétrie', selected: true, domains: [
      'www.google-analytics.com', 'analytics.google.com', 'pixel.facebook.com',
      'connect.facebook.net', 'bat.bing.com', 'sb.scorecardresearch.com',
      'app-measurement.com', 'api.segment.io', 'cdn.mxpnl.com', 'script.hotjar.com']},
    {id: 'security', name: 'Sécurité · témoin synthétique', selected: true,
      domains: ['malware.testcategory.com']},
    {id: 'family', name: 'Contrôle parental · facultatif', selected: false,
      domains: ['nudity.testcategory.com']},
    {id: 'social', name: 'Réseaux sociaux · facultatif', selected: false,
      domains: ['www.youtube.com', 'www.tiktok.com', 'www.instagram.com', 'www.facebook.com', 'www.reddit.com']}
  ];
  const controls = ['example.com', 'www.mozilla.org', 'www.wikipedia.org'];
  const labels = {reachable: 'Joignable', network_error: 'Échec réseau / filtrage possible',
    timeout: 'Délai dépassé / cause inconnue', cancelled: 'Annulée', csp_error: 'Restriction de cette page'};
  const escapeHTML = value => String(value).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  function parseCustom(text) {
    const domains = new Set();
    for (const [index, raw] of text.split(/\r?\n/).entries()) {
      let line = raw.split('#', 1)[0].trim().toLowerCase();
      if (!line) continue;
      if (line.startsWith('||') && line.endsWith('^')) line = line.slice(2, -1);
      const fields = line.split(/\s+/);
      if (['0.0.0.0', '127.0.0.1', '::', '::1'].includes(fields[0]) && fields.length > 1) fields.shift();
      for (let domain of fields) {
        domain = domain.replace(/\.$/, '');
        if (['localhost', 'localhost.localdomain', 'local', 'ip6-localhost', '0.0.0.0', '::1'].includes(domain)) continue;
        if (domain.length > 253 || !domain.includes('.') || /^[\d.]+$/.test(domain) ||
            !domain.split('.').every(part => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part)))
          throw Error('Ligne ' + (index + 1) + ' : domaine ASCII/Punycode attendu, sans URL ni chemin.');
        domains.add(domain);
        if (domains.size > MAX_CASES) throw Error(MAX_CASES + ' domaines maximum.');
      }
    }
    return [...domains];
  }
  function makeCases(selected, custom) {
    const cases = controls.map(domain => ({domain, category: 'Témoins légitimes', expect: 'allow'}));
    const seen = new Set(controls);
    for (const group of catalog.filter(group => selected.includes(group.id))) {
      for (const domain of group.domains) if (!seen.has(domain)) {
        seen.add(domain); cases.push({domain, category: group.name, expect: 'block'});
      }
    }
    for (const domain of parseCustom(custom)) if (!seen.has(domain)) {
      seen.add(domain); cases.push({domain, category: 'Personnalisé', expect: 'block'});
    }
    if (cases.length > MAX_CASES) throw Error(MAX_CASES + ' sondes maximum, témoins compris.');
    if (cases.length === controls.length) throw Error('Sélectionnez une catégorie ou ajoutez des domaines.');
    return cases;
  }
  async function probe(test, timeout, signal, fetcher, cspHosts) {
    const controller = new AbortController();
    let timedOut = false;
    const cancel = () => controller.abort();
    if (signal.aborted) return {...test, outcome: 'cancelled', elapsed_ms: 0};
    signal.addEventListener('abort', cancel, {once: true});
    const timer = setTimeout(() => {timedOut = true; controller.abort();}, timeout);
    const start = performance.now();
    let outcome;
    try {
      const nonce = Math.random().toString(36).slice(2) + '-' + Date.now();
      await fetcher('https://' + test.domain + '/favicon.ico?yetdns_probe=' + nonce, {
        method: 'HEAD', mode: 'no-cors', credentials: 'omit', cache: 'no-store',
        redirect: 'follow', referrerPolicy: 'no-referrer', signal: controller.signal
      });
      outcome = signal.aborted ? 'cancelled' : 'reachable';
    } catch (_) {
      outcome = signal.aborted ? 'cancelled' : timedOut ? 'timeout' :
        cspHosts.has(test.domain) ? 'csp_error' : 'network_error';
    } finally {
      clearTimeout(timer); signal.removeEventListener('abort', cancel);
    }
    return {...test, outcome, elapsed_ms: Math.round(performance.now() - start)};
  }
  async function runSuite(cases, options, onProgress = () => {}, fetcher = root.fetch.bind(root), cspHosts = new Set()) {
    const results = new Array(cases.length);
    let completed = 0;
    const publish = (result, index) => {results[index] = result; onProgress(++completed, cases.length, result);};
    const initial = cases.filter(test => test.expect === 'allow');
    for (let i = 0; i < initial.length; ++i) publish(await probe(initial[i], options.timeout, options.signal, fetcher, cspHosts), i);
    const healthyControls = results.filter(r => r && r.expect === 'allow' && r.outcome === 'reachable').length;
    // A broken connection must never produce a misleading 100% protection result.
    if (healthyControls < 2 || options.signal.aborted) return results.filter(Boolean);
    let next = initial.length;
    async function worker() {
      while (next < cases.length && !options.signal.aborted) {
        const index = next++;
        publish(await probe(cases[index], options.timeout, options.signal, fetcher, cspHosts), index);
      }
    }
    await Promise.all(Array.from({length: Math.min(options.concurrency, cases.length - initial.length)}, worker));
    for (const result of results.filter(Boolean)) if (cspHosts.has(result.domain) && result.outcome !== 'reachable' && result.outcome !== 'cancelled') result.outcome = 'csp_error';
    return results.filter(Boolean);
  }
  function summarize(results, planned) {
    const controlRows = results.filter(r => r.expect === 'allow');
    const healthy = controlRows.filter(r => r.outcome === 'reachable').length;
    const trusted = healthy === controls.length;
    const complete = results.length === planned && !results.some(r => r.outcome === 'cancelled');
    const groups = {};
    for (const row of results.filter(r => r.expect === 'block')) {
      const group = groups[row.category] ||= {total: 0, reachable: 0, apparent: 0, unknown: 0};
      group.total++;
      if (row.outcome === 'reachable') group.reachable++;
      else if (row.outcome === 'network_error') group.apparent++;
      else group.unknown++;
    }
    for (const group of Object.values(groups)) group.apparent_percent = trusted && complete && group.total ? Math.round(group.apparent * 1000 / group.total) / 10 : null;
    return {planned, completed: results.length, control_total: controls.length, controls_reachable: healthy,
      reliable_controls: trusted, complete,
      conclusion: healthy < 2 ? 'Test non concluant : témoins injoignables.' : !trusted ?
        'Témoins partiellement accessibles : résultat non concluant sur le niveau de protection.' :
        'Résultats par catégorie : filtrage apparent, cause DNS non confirmée.', groups};
  }
  function reportMarkup(report) {
    const s = report.summary, e = escapeHTML;
    const date = new Date(report.generated_at).toLocaleString('fr-FR', {timeZone: report.timezone});
    const categories = Object.entries(s.groups).map(([name, group]) => '<tr><td>' + e(name) + '</td><td>' + group.apparent + '</td><td>' + group.reachable + '</td><td>' + group.unknown + '</td><td>' + (group.apparent_percent === null ? 'Non concluant' : group.apparent_percent + ' %') + '</td></tr>').join('');
    const rows = report.results.map(row => '<tr><td>' + e(row.domain) + '</td><td>' + e(row.category) + '</td><td>' + (row.expect === 'allow' ? 'Accessible' : 'Bloqué') + '</td><td>' + e(labels[row.outcome] || row.outcome) + '</td><td>' + row.elapsed_ms + ' ms</td></tr>').join('');
    return '<section><h2>Rapport de cette connexion</h2><p>' + e(date) + ' · ' + e(report.timezone) + '</p><p class="warn">' + e(s.conclusion) + '</p><div class="grid"><div class="card">Témoins joignables<strong>' + s.controls_reachable + '/' + s.control_total + '</strong></div><div class="card">Sondes terminées<strong>' + s.completed + '/' + s.planned + '</strong></div><div class="card">DNS utilisé<strong>Non identifiable</strong></div></div><p>' + (s.complete ? 'Exécution terminée.' : 'Exécution partielle ou arrêtée.') + ' Échantillon v' + e(report.sample_version) + '.</p></section>' +
      '<section><h2>Couverture apparente par catégorie</h2><div class="table-wrap"><table><thead><tr><th>Catégorie</th><th>Échecs réseau</th><th>Joignables</th><th>Inconnus / annulés</th><th>Inaccessibilité indicative</th></tr></thead><tbody>' + categories + '</tbody></table></div><p class="muted">Un échec réseau peut venir du DNS, d’une extension, de TLS ou du serveur. Les délais dépassés ne sont pas comptés comme protégés. Un témoin indisponible invalide les pourcentages. Aucun score global de sécurité n’est déduit de cet échantillon.</p></section>' +
      '<section><h2>Détail des sondes</h2><div class="table-wrap"><table><thead><tr><th>Domaine</th><th>Catégorie</th><th>Politique souhaitée</th><th>Observation</th><th>Durée</th></tr></thead><tbody>' + rows + '</tbody></table></div></section>' +
      '<section><h2>Méthode et limites</h2><p>Requêtes HTTPS HEAD exécutées par le navigateur de cet appareil, sans cookies, avec les redirections HTTPS du serveur. Le serveur qui héberge cette interface ne résout pas les domaines à votre place. Les réponses HTTP opaques ne révèlent ni leur statut ni les réponses DNS A/AAAA. SafeSearch, identité du résolveur et résistance aux contournements ne sont pas mesurés.</p><p>Ce résultat décrit uniquement cet échantillon, ce navigateur et cet instant ; il ne certifie pas la protection contre les menaces réelles. Les domaines synthétiques ne remplacent pas une évaluation complète.</p><small>Sources : Cloudflare 1.1.1.1 setup · DNS Filter Test /my-connection (méthode étudiée). Code YetDNS original.</small></section>';
  }
  function exportHTML(report) {
    return '<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>Rapport YetDNS</title><style>body{max-width:1100px;margin:30px auto;padding:15px;font:15px system-ui;background:#0c111b;color:#e8edf6}section{padding:20px;border:1px solid #42516b;border-radius:12px;margin:15px 0}.grid{display:flex;gap:30px;flex-wrap:wrap}.card strong{display:block;font-size:25px}table{border-collapse:collapse;width:100%;font-size:13px}td,th{text-align:left;padding:9px;border-bottom:1px solid #42516b}.table-wrap{overflow:auto}.warn{color:#ffce80}p{line-height:1.6}td:first-child{overflow-wrap:anywhere}@media print{body{background:white;color:black}.warn{color:black}}</style><h1>YetDNS · Rapport du navigateur</h1>' + reportMarkup(report) + '</html>';
  }
  function init() {
    const $ = id => root.document.getElementById(id);
    let lastReport = null, running = null;
    const cspHosts = new Set();
    root.document.addEventListener('securitypolicyviolation', event => {
      if (event.effectiveDirective === 'connect-src') {try {cspHosts.add(new URL(event.blockedURI).hostname);} catch (_) {}}
    });
    for (const group of catalog) {
      const label = root.document.createElement('label'), input = root.document.createElement('input');
      input.type = 'checkbox'; input.value = group.id; input.checked = group.selected;
      label.append(input, ' ' + group.name + ' (' + group.domains.length + ')'); $('categories').append(label);
    }
    $('test-file').onchange = async () => {
      try {const file = $('test-file').files[0]; if (!file) return; if (file.size > 1024 * 1024) throw Error('Fichier limité à 1 Mo.'); $('custom-domains').value = await file.text(); $('test-error').textContent = '';}
      catch (error) {$('test-error').textContent = error.message;}
    };
    function download(content, type, extension) {
      const url = URL.createObjectURL(new Blob([content], {type})), link = root.document.createElement('a');
      link.href = url; link.download = 'yetdns-report-' + lastReport.generated_at.replace(/[:.]/g, '-') + '.' + extension;
      link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    $('export-html').onclick = () => download(exportHTML(lastReport), 'text/html;charset=utf-8', 'html');
    $('export-json').onclick = () => download(JSON.stringify(lastReport, null, 2), 'application/json', 'json');
    $('stop-test').onclick = () => running?.abort();
    $('start-test').onclick = async () => {
      if (running) return;
      $('test-error').textContent = '';
      try {
        const selected = Array.from($('categories').querySelectorAll('input:checked'), input => input.value);
        const cases = makeCases(selected, $('custom-domains').value), timeout = Number($('probe-timeout').value), concurrency = Number($('probe-concurrency').value);
        if (!Number.isInteger(timeout) || timeout < 1000 || timeout > 15000 || !Number.isInteger(concurrency) || concurrency < 1 || concurrency > 6) throw Error('Délai : 1000–15000 ms ; sondes simultanées : 1–6.');
        running = new AbortController(); cspHosts.clear(); lastReport = null;
        $('start-test').disabled = true; $('stop-test').disabled = false; $('export-html').disabled = $('export-json').disabled = true;
        $('report').replaceChildren(); $('test-progress').max = cases.length; $('test-progress').value = 0;
        const results = await runSuite(cases, {timeout, concurrency, signal: running.signal}, (count, total, row) => {
          $('test-progress').value = count; $('progress-text').textContent = count + '/' + total + ' · ' + row.domain;
        }, root.fetch.bind(root), cspHosts);
        lastReport = {schema: 1, sample_version: '2026-10-18', generated_at: new Date().toISOString(),
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, execution: 'browser',
          settings: {timeout_ms: timeout, concurrency, selected}, summary: summarize(results, cases.length), results};
        $('report').innerHTML = reportMarkup(lastReport); $('export-html').disabled = $('export-json').disabled = false;
        $('progress-text').textContent = lastReport.summary.complete ? 'Test terminé. Rapport disponible.' : 'Test partiel : consultez le rapport.';
        // Only the optional local PC launcher accepts reports; the ESP never receives them.
        if (['127.0.0.1', 'localhost'].includes(root.location.hostname) && new URLSearchParams(root.location.search).has('save')) {
          const saved = await root.fetch('/report', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-YetDNS-Test': '1'},
            body: JSON.stringify({report: lastReport, html: exportHTML(lastReport)})});
          if (!saved.ok) throw Error('Rapport affiché, mais sauvegarde locale impossible.');
        }
      } catch (error) {$('test-error').textContent = error.message;}
      finally {running = null; $('start-test').disabled = false; $('stop-test').disabled = true;}
    };
    $('start-test').disabled = false;
    if (new URLSearchParams(root.location.search).has('run')) $('start-test').click();
  }
  const api = {catalog, controls, labels, parseCustom, makeCases, probe, runSuite, summarize, reportMarkup, exportHTML};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root.document) init();
})(typeof window === 'undefined' ? globalThis : window);
