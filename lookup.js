#!/usr/bin/env node
// Longest-prefix lookups against bytedance-feed.json (ByteDance set + network set).
//   node lookup.js explain 71.18.252.10 2a01:4f8::1   one JSON line per IP on stdout, summary on stderr
//   node lookup.js 71.18.252.10                       one tab-separated line per IP
//   cat access.log | node lookup.js                   classify the first IP of each line + totals
//   cat ips.txt | node lookup.js explain              explain mode over stdin
'use strict';

const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const feedPath = process.env.FEED || path.join(__dirname, 'bytedance-feed.json');
const feed = JSON.parse(fs.readFileSync(feedPath, 'utf8'));
const networks = feed.networks || { prefixes: [], asns: {}, providers: {} };

const CATEGORY_PRIORITY = { bytedance: 0, crawler: 1, relay: 2, vpn: 3, proxy: 4, cloud: 5, hosting: 6 };
const CATEGORY_NOTE = {
  bytedance: 'ByteDance-operated network (crawlers, app backends, Volcengine/BytePlus cloud tenants)',
  cloud: 'cloud infrastructure: the visitor is whoever runs code there, not necessarily the provider',
  hosting: 'hosting/datacenter range: usually a server, bot or self-hosted proxy rather than a person',
  vpn: 'VPN exit node: a real person whose location is hidden',
  proxy: 'commercial proxy network: traffic is relayed for a third party',
  crawler: 'published crawler range: check that the User-Agent matches the crawler',
  relay: 'iCloud Private Relay egress: a real Apple user whose IP is hidden',
};

function toBig(ip) {
  if (net.isIPv4(ip)) return { family: 4, n: ip.split('.').reduce((a, o) => (a << 8n) | BigInt(Number(o)), 0n) };
  if (!net.isIPv6(ip)) return null;
  let s = ip.replace(/%.*$/, '');
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const n = toBig(v4[1]).n;
    s = s.slice(0, -v4[1].length) + (n >> 16n).toString(16) + ':' + (n & 0xffffn).toString(16);
  }
  const [h, t] = s.split('::');
  const hg = h ? h.split(':') : [];
  const tg = t !== undefined && t ? t.split(':') : [];
  const groups = t !== undefined ? [...hg, ...Array(8 - hg.length - tg.length).fill('0'), ...tg] : hg;
  return { family: 6, n: groups.reduce((a, g) => (a << 16n) | BigInt(parseInt(g, 16)), 0n) };
}

// Index: family -> prefix length -> network (hex) -> entries. Lookup probes each length, longest first.
const index = { 4: new Map(), 6: new Map() };
for (const entry of [...feed.prefixes, ...networks.prefixes]) {
  const [ip, len] = entry.prefix.split('/');
  const { family, n } = toBig(ip);
  const byLen = index[family];
  if (!byLen.has(Number(len))) byLen.set(Number(len), new Map());
  const m = byLen.get(Number(len));
  const key = n.toString(16);
  if (!m.has(key)) m.set(key, []);
  m.get(key).push(entry);
}
const lengths = { 4: [...index[4].keys()].sort((a, b) => b - a), 6: [...index[6].keys()].sort((a, b) => b - a) };

// All entries covering the IP, most specific first; equal lengths ordered by category priority.
function matches(ip) {
  const addr = toBig(ip);
  if (!addr) return null;
  const bits = addr.family === 4 ? 32 : 128;
  const out = [];
  for (const len of lengths[addr.family]) {
    const host = (1n << BigInt(bits - len)) - 1n;
    const hit = index[addr.family].get(len).get((addr.n & ~host).toString(16));
    if (hit) out.push(...[...hit].sort((a, b) => CATEGORY_PRIORITY[a.category] - CATEGORY_PRIORITY[b.category]));
  }
  return out;
}

function holderOf(e) {
  if (e.category === 'bytedance') return (feed.asns[e.asn] && feed.asns[e.asn].holder) || 'ByteDance';
  return (e.asn && networks.asns[e.asn] && networks.asns[e.asn].holder) ||
    (networks.providers[e.provider] && networks.providers[e.provider].holder) || e.provider;
}

function confidence(e) {
  const holder = holderOf(e);
  if (e.category === 'bytedance') {
    if (e.announced && e.rpki === 'valid') return ['high', `announced in BGP by AS${e.asn} and RPKI-valid`];
    if (e.announced && e.rpki === 'invalid') return ['medium', `announced by AS${e.asn} but RPKI-invalid (possible leak or misconfiguration)`];
    if (e.announced) return ['high', `announced in BGP by AS${e.asn} (no ROA published)`];
    if (e.rpki === 'valid') return ['medium', `RPKI-authorised for AS${e.asn} but not visible in global BGP`];
    return ['medium', 'hand-curated entry from known-usage.json'];
  }
  const s = e.sources;
  if (s.includes('ripestat') || s.includes('bgptools')) return ['high', `announced in BGP by AS${e.asn} (${holder})`];
  if (s.every((x) => x === 'ripe-db')) return ['medium', `assigned to ${holder} in the RIPE database (customer assignment, not routing data)`];
  return ['high', `published by ${holder} (${s.join(', ')})`];
}

function explain(ip) {
  const all = matches(ip);
  if (all === null) return { ip, error: 'invalid IP address' };
  if (!all.length) return { ip, match: null, confidence: 'none', reason: 'not in any feed layer', also: [] };
  const [best, ...rest] = all;
  const [level, reason] = confidence(best);
  const match = {
    prefix: best.prefix,
    provider: best.provider,
    category: best.category,
    tag: best.tag,
    asn: best.asn ?? null,
    holder: holderOf(best),
    // Published feeds (AWS, crawlers, RIPE DB...) are not checked against BGP: null = unknown.
    announced: best.category === 'bytedance' ? best.announced
      : best.sources.some((x) => x === 'ripestat' || x === 'bgptools') ? true : null,
    sources: best.sources,
  };
  if (best.rpki) match.rpki = best.rpki;
  if (best.strict !== undefined) match.strict = best.strict; // false = not in the strict feed.all.txt
  if (best.cloud) match.cloud = best.cloud;
  if (best.service) match.service = best.service;
  return {
    ip,
    match,
    confidence: level,
    reason,
    note: CATEGORY_NOTE[best.category],
    also: rest.map((e) => ({ prefix: e.prefix, provider: e.provider, category: e.category })),
  };
}

function summary(r) {
  if (r.error) return `${r.ip}: ${r.error}`;
  if (!r.match) return `${r.ip}: no match (not ByteDance, cloud, hosting, VPN, proxy, crawler or relay space)`;
  const m = r.match;
  const flags = [m.announced === null ? 'BGP not checked' : m.announced ? 'announced' : 'not announced'];
  if (m.rpki) flags.push(`RPKI ${m.rpki}`);
  if (m.strict === false) flags.push('not in strict feed.all.txt');
  if (m.cloud) flags.push(`inside ${m.cloud.provider} ${m.cloud.prefix}`);
  if (m.service) flags.push(`service ${m.service}`);
  let s = `${r.ip}: ${m.prefix} · ${m.provider}${m.asn ? ` AS${m.asn}` : ''} (${m.holder}) · ${m.category} · ` +
    `${flags.join(', ')} · sources ${m.sources.join(',')} · confidence ${r.confidence}: ${r.reason}`;
  if (r.also.length) s += `\n    also inside: ${r.also.map((a) => `${a.prefix} ${a.provider}/${a.category}`).join('; ')}`;
  return s;
}

function readStdinLines(onLine, onEnd) {
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (d) => {
    buf += d;
    const lines = buf.split('\n');
    buf = lines.pop();
    lines.forEach(onLine);
  });
  process.stdin.on('end', () => {
    if (buf) onLine(buf);
    onEnd();
  });
}

const ipRe = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:.]+)/;
const args = process.argv.slice(2);

if (args[0] === 'explain') {
  const run = (ip) => {
    const r = explain(ip.trim());
    console.log(JSON.stringify(r));
    console.error(summary(r));
  };
  if (args.length > 1) args.slice(1).forEach(run);
  else readStdinLines((line) => { const m = ipRe.exec(line); if (m) run(m[1]); }, () => {});
} else if (args.length) {
  for (const ip of args) {
    const all = matches(ip);
    const e = all && all[0];
    console.log(e ? `${ip}\t${e.prefix}\t${e.provider}\t${e.category}\t${e.asn ? 'AS' + e.asn : '-'}` : `${ip}\t-`);
  }
} else {
  const byCategory = new Map(), byProvider = new Map();
  let total = 0, hits = 0;
  const bump = (m, k) => m.set(k, (m.get(k) || 0) + 1);
  readStdinLines((line) => {
    const m = ipRe.exec(line);
    if (!m || !net.isIP(m[1])) return;
    total++;
    const all = matches(m[1]);
    if (!all || !all.length) return;
    const e = all[0];
    hits++;
    bump(byCategory, e.category);
    bump(byProvider, `${e.category}/${e.provider}`);
    console.log(`${m[1]}\t${e.prefix}\t${e.provider}\t${e.category}`);
  }, () => {
    console.error(`\n${hits}/${total} requests matched a feed layer`);
    for (const [k, n] of [...byCategory].sort((a, b) => b[1] - a[1])) console.error(`  ${k}: ${n}`);
    console.error('  by provider:');
    for (const [k, n] of [...byProvider].sort((a, b) => b[1] - a[1]).slice(0, 25)) console.error(`    ${k}: ${n}`);
  });
}
