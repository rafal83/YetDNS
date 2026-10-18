'use strict';
const assert = require('node:assert/strict');
const diagnostic = require('../main/diagnostic.js');

async function main() {
  assert.deepEqual(diagnostic.parseCustom('# comment\n0.0.0.0 ADS.EXAMPLE.com ads2.example.com\n||ads.example.com^\n'), ['ads.example.com', 'ads2.example.com']);
  for (const bad of ['https://example.com', 'example.com/path', '127.0.0.1', 'a..com', 'x.com<script>']) assert.throws(() => diagnostic.parseCustom(bad));
  const cases = diagnostic.makeCases([], 'blocked.example\nslow.example\nopen.example');
  const seen = [], signal = new AbortController();
  let active = 0, peak = 0;
  const fetcher = async (url, options) => {
    assert.equal(options.method, 'HEAD'); assert.equal(options.credentials, 'omit');
    assert.equal(options.redirect, 'follow'); assert.equal(options.mode, 'no-cors');
    seen.push(url); active++; peak = Math.max(peak, active);
    try {
      if (url.includes('blocked.example')) throw new TypeError('Failed to fetch');
      if (url.includes('slow.example')) return await new Promise((_, reject) => options.signal.addEventListener('abort', () => reject(new Error('abort'))));
      await new Promise(resolve => setTimeout(resolve, 2)); return {type: 'opaque'};
    } finally {active--;}
  };
  const results = await diagnostic.runSuite(cases, {timeout: 20, concurrency: 2, signal: signal.signal}, () => {}, fetcher);
  assert(peak <= 2); assert.equal(seen.length, cases.length);
  const summary = diagnostic.summarize(results, cases.length);
  assert.equal(summary.controls_reachable, 3); assert(summary.complete);
  assert.equal(summary.groups.Personnalisé.apparent, 1);
  assert.equal(summary.groups.Personnalisé.unknown, 1);
  assert.equal(summary.groups.Personnalisé.reachable, 1);
  assert.equal(summary.groups.Personnalisé.apparent_percent, 33.3); // timeout is never counted as protected
  const offline = await diagnostic.runSuite(cases, {timeout: 20, concurrency: 2, signal: signal.signal}, () => {}, async () => {throw Error('offline');});
  assert.equal(offline.length, 3); // no misleading all-blocked score when the connection is broken
  assert(!diagnostic.summarize(offline, cases.length).complete);
  assert.deepEqual(diagnostic.summarize(offline, cases.length).groups, {});
  const partial = diagnostic.summarize(results.slice(0, -1), cases.length);
  assert.equal(partial.groups.Personnalisé.apparent_percent, null);
  const csp = new Set(['blocked.example']);
  const restricted = await diagnostic.runSuite(cases, {timeout: 20, concurrency: 1, signal: signal.signal}, () => {}, fetcher, csp);
  assert.equal(restricted.find(r => r.domain === 'blocked.example').outcome, 'csp_error');
  const cancel = new AbortController(); cancel.abort();
  const cancelled = await diagnostic.runSuite(cases, {timeout: 20, concurrency: 2, signal: cancel.signal}, () => {}, fetcher);
  assert(cancelled.every(r => r.outcome === 'cancelled'));
  const report = {generated_at: '2026-10-18T12:00:00Z', sample_version: 'test', timezone: 'Europe/Paris', summary, results: results.concat([{domain: '<script>alert(1)</script>', category: '<img>', expect: 'block', outcome: 'timeout', elapsed_ms: 1}])};
  const html = diagnostic.exportHTML(report);
  assert(!html.includes('<script>')); assert(html.includes('&lt;script&gt;'));
  assert(html.includes("default-src 'none'"));
  console.log('Browser diagnostic: controls, timeouts, cancellation, CSP, bounded concurrency, parsers and offline HTML passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});
