#!/usr/bin/env node
// Builds the IP classification feed:
//   - ByteDance set (precision): IRR whois (APNIC + RADB) + BGP (RIPEstat, bgp.tools), kept only if
//     announced in BGP or RPKI-valid.
//   - Network set (recall): cloud (Alibaba, AWS, GCP, Azure, Oracle), hosting, proxy, VPN, crawler, relay.
// Writes bytedance-feed.json (structured record) and feed.all.txt (flat "<cidr> <tag>" file).
// Zero dependencies, Node >= 18. Exits non-zero and leaves existing files untouched on any failure.
'use strict';

const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// ByteDance-family ASNs, verified by registered holder name (RIPEstat as-overview, 2026-10-09).
// `core: true` means the ASN must return prefixes from RIPEstat or the run fails.
const ASNS = {
  396986: { tag: 'bytedance', holder: 'Bytedance Inc.', core: true },
  137775: { tag: 'bytedance', holder: 'Beijing Bytedance Network Technology Co., Ltd.' },
  138699: { tag: 'tiktok', holder: 'TIKTOK PTE. LTD.', core: true },
  11983: { tag: 'tiktok', holder: 'Tiktok U.S. Data Security Inc.' },
  137718: { tag: 'volcengine', holder: 'Beijing Volcano Engine Technology Co., Ltd.', core: true },
  150436: { tag: 'byteplus', holder: 'Byteplus Pte. Ltd.', core: true },
  398175: { tag: 'lark', holder: 'LARK ENTERPRISE APPLICATIONS INC.' },
};

// Cloud networks discovered through BGP announcements (Alibaba publishes no range list).
const CLOUD_ASN_GROUPS = [
  { provider: 'alibaba', category: 'cloud', tag: 'alibaba', holder: 'Alibaba Cloud',
    asns: [45102, 37963, 24429, 134963] },
];

// Clouds with official machine-readable range files.
const CLOUD_FEEDS = [
  { provider: 'aws', category: 'cloud', tag: 'aws', holder: 'Amazon Web Services', source: 'aws',
    url: 'https://ip-ranges.amazonaws.com/ip-ranges.json', min: 1000 },
  { provider: 'gcp', category: 'cloud', tag: 'gcp', holder: 'Google Cloud', source: 'gcp',
    url: 'https://www.gstatic.com/ipranges/cloud.json', min: 100 },
  { provider: 'azure', category: 'cloud', tag: 'azure', holder: 'Microsoft Azure', source: 'azure',
    url: 'https://www.microsoft.com/en-us/download/details.aspx?id=56519', min: 1000 },
];

// Tie-break for identical CIDRs from different providers (lower wins in lookups; also txt order).
const CATEGORY_PRIORITY = { bytedance: 0, crawler: 1, relay: 2, vpn: 3, proxy: 4, cloud: 5, hosting: 6 };

const OUT_DIR = process.env.FEED_OUT_DIR || __dirname;
const FEED_FILE = path.join(OUT_DIR, 'bytedance-feed.json');
const LASTGOOD_FILE = path.join(OUT_DIR, 'bytedance-feed.lastgood.json');
const ALL_TXT_FILE = path.join(OUT_DIR, 'feed.all.txt');
const ALL_TXT_LASTGOOD_FILE = path.join(OUT_DIR, 'feed.all.lastgood.txt');
const CURATED_FILE = path.join(__dirname, 'known-usage.json');
const DATACENTER_FILE = path.join(__dirname, 'datacenter-asns.json');
const VPN_FILE = path.join(__dirname, 'vpn-asns.json');
const CRAWLER_FILE = path.join(__dirname, 'crawler-prefixes.json');

const MIN_BYTEDANCE = 100; // fewer ByteDance prefixes than this means something upstream broke
const MAX_SHRINK = 0.3; // fail if any provider shrinks by more than 30% vs. the current feed
const RIPESTAT_CONCURRENCY = 4;
const SKIP_BGPTOOLS = process.env.SKIP_BGPTOOLS === '1';
// On by default: feed.all.txt gets only ByteDance prefixes marked `strict` (see the serialise step).
const STRICT_ANNOUNCED = process.env.STRICT_ANNOUNCED !== '0';
const ALLOW_SHRINK = process.env.ALLOW_SHRINK === '1';

const CONTACT = process.env.FEED_CONTACT ||
  (process.env.GITHUB_REPOSITORY ? `https://github.com/${process.env.GITHUB_REPOSITORY}` : 'local run');
const USER_AGENT = `bytedance-ip-feed/2.0 (+${CONTACT})`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const log = (...a) => console.error('[feed]', ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class SourceError extends Error {}

async function withRetry(label, fn, attempts = 4) {
  let delay = 3000;
  for (let i = 1; ; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i >= attempts || err.fatal) throw new SourceError(`${label}: ${err.message}`);
      log(`${label} failed (attempt ${i}/${attempts}): ${err.message}; retrying in ${delay / 1000}s`);
      await sleep(delay);
      delay *= 3;
    }
  }
}

async function fetchChecked(url, timeoutMs, accept = 'application/json') {
  const res = await fetch(url, {
    headers: { 'User-Agent': USER_AGENT, Accept: accept },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
  if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status}`), { fatal: true });
  return res;
}

const fetchJson = (label, url, timeoutMs = 120000) =>
  withRetry(label, async () => {
    const res = await fetchChecked(url, timeoutMs);
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch {
      throw new Error(`invalid JSON (${text.length} bytes)`);
    }
  });

const fetchText = (label, url, timeoutMs = 120000) =>
  withRetry(label, async () => (await fetchChecked(url, timeoutMs, '*/*')).text());

// Runs async tasks with a concurrency limit; rejects on the first failure.
async function pool(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

// --- CIDR math (BigInt, both families) -------------------------------------

function ipToBig(ip, family) {
  if (family === 4) {
    return ip.split('.').reduce((acc, o) => (acc << 8n) | BigInt(Number(o)), 0n);
  }
  let s = ip;
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const n = ipToBig(v4[1], 4);
    s = s.slice(0, -v4[1].length) + ((n >> 16n).toString(16)) + ':' + ((n & 0xffffn).toString(16));
  }
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail ? tail.split(':') : [];
  const groups = tail !== undefined ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
}

function bigToIp(n, family) {
  if (family === 4) return [24n, 16n, 8n, 0n].map((s) => Number((n >> s) & 0xffn)).join('.');
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  // RFC 5952: compress the longest run (>= 2) of zero groups
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (best < 0) return hex.join(':');
  return hex.slice(0, best).join(':') + '::' + hex.slice(best + bestLen).join(':');
}

const familyBits = (family) => (family === 4 ? 32 : 128);

function makePrefix(family, start, len) {
  const host = (1n << BigInt(familyBits(family) - len)) - 1n;
  return { family, len, start, end: start | host, cidr: `${bigToIp(start, family)}/${len}` };
}

// Parses and canonicalises a CIDR (host bits zeroed, RFC 5952). Returns null if malformed.
function parseCidr(str) {
  const m = /^\s*([0-9a-fA-F:.]+)\/(\d{1,3})\s*$/.exec(String(str));
  if (!m) return null;
  const family = net.isIPv4(m[1]) ? 4 : net.isIPv6(m[1]) ? 6 : 0;
  if (!family) return null;
  const bits = familyBits(family);
  const len = Number(m[2]);
  if (len > bits) return null;
  const host = (1n << BigInt(bits - len)) - 1n;
  const raw = ipToBig(m[1], family);
  const p = makePrefix(family, raw & ~host & ((1n << BigInt(bits)) - 1n), len);
  p.hostBitsSet = p.start !== raw;
  return p;
}

// Smallest set of CIDRs exactly covering [start, end].
function rangeToPrefixes(family, start, end) {
  const bits = familyBits(family);
  const out = [];
  while (start <= end) {
    let size = 0;
    while (size < bits) {
      const block = 1n << BigInt(size + 1);
      if ((start & (block - 1n)) !== 0n || start + block - 1n > end) break;
      size++;
    }
    out.push(makePrefix(family, start, bits - size));
    start += 1n << BigInt(size);
  }
  return out;
}

// Merges overlapping/adjacent prefixes into the minimal covering CIDR set.
function collapse(prefixes) {
  const out = [];
  for (const family of [4, 6]) {
    const list = prefixes.filter((p) => p.family === family).sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
    let cur = null;
    for (const p of list) {
      if (cur && p.start <= cur.end + 1n) {
        if (p.end > cur.end) cur.end = p.end;
      } else {
        if (cur) out.push(...rangeToPrefixes(family, cur.start, cur.end));
        cur = { start: p.start, end: p.end };
      }
    }
    if (cur) out.push(...rangeToPrefixes(family, cur.start, cur.end));
  }
  return out;
}

// Keep IPv4 /8../32 and IPv6 /16../128.
function lengthOk(p) {
  return p.family === 4 ? p.len >= 8 && p.len <= 32 : p.len >= 16 && p.len <= 128;
}

const comparePrefixes = (a, b) =>
  a.family - b.family || (a.start < b.start ? -1 : a.start > b.start ? 1 : a.len - b.len);

// Exact-match index by (family, length, network); answers "which indexed prefixes cover p".
class PrefixIndex {
  constructor() { this.maps = { 4: new Map(), 6: new Map() }; }
  add(p, value) {
    const byLen = this.maps[p.family];
    if (!byLen.has(p.len)) byLen.set(p.len, new Map());
    const m = byLen.get(p.len);
    const key = p.start.toString(16);
    if (!m.has(key)) m.set(key, []);
    m.get(key).push(value);
  }
  covering(p) {
    const out = [];
    const bits = familyBits(p.family);
    for (const [len, m] of this.maps[p.family]) {
      if (len > p.len) continue;
      const host = (1n << BigInt(bits - len)) - 1n;
      const hit = m.get((p.start & ~host).toString(16));
      if (hit) out.push(...hit);
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

// Raw whois over TCP/43. Rejects on timeout, connection errors and server-side error banners.
function whoisQuery(host, query, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    let out = '';
    const sock = net.connect(43, host, () => sock.write(query + '\r\n'));
    sock.setEncoding('utf8');
    sock.setTimeout(timeoutMs, () => sock.destroy(new Error('timeout')));
    sock.on('data', (d) => (out += d));
    sock.on('error', reject);
    sock.on('close', (hadError) => {
      if (hadError) return;
      // APNIC: "%ERROR:201: access denied" (rate limit / block); RADB uses "% Error"
      const err = out.match(/^%\s*ERROR:?.*$/im);
      if (err && !/no entries found/i.test(err[0])) return reject(new Error(err[0].trim()));
      resolve(out);
    });
  });
}

async function fetchIrr(host, label) {
  const results = []; // { cidr, asn }
  for (const asn of Object.keys(ASNS)) {
    const text = await withRetry(`${label} AS${asn}`, () => whoisQuery(host, `-K -i origin AS${asn}`));
    if (!/route6?:|no entries found|^%/im.test(text)) {
      throw new SourceError(`${label} AS${asn}: unrecognised response: ${JSON.stringify(text.slice(0, 200))}`);
    }
    const routes = [...text.matchAll(/^route6?:\s*(\S+)/gim)].map((m) => m[1]);
    for (const r of routes) results.push({ cidr: r, asn: Number(asn) });
    log(`${label} AS${asn}: ${routes.length} route objects`);
    await sleep(1500); // stay well under per-IP query limits
  }
  if (results.length === 0) throw new SourceError(`${label}: no route objects for any ASN`);
  return results;
}

async function fetchRipestat(asn) {
  const url = `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}&sourceapp=bytedance-ip-feed`;
  const j = await fetchJson(`ripestat AS${asn}`, url);
  if (j.status !== 'ok' || !j.data || !Array.isArray(j.data.prefixes)) {
    throw new SourceError(`ripestat AS${asn}: unexpected payload (status=${j.status})`);
  }
  return j.data.prefixes.map((p) => p.prefix);
}

// bgp.tools full table: one JSON object per line, {"CIDR","ASN","Hits"}. Streamed, ~1.5M lines.
async function fetchBgptools(wanted) {
  return withRetry('bgp.tools', async () => {
    const res = await fetchChecked('https://bgp.tools/table.jsonl', 15 * 60 * 1000);
    const found = [];
    const decoder = new TextDecoder();
    let buf = '', lines = 0;
    const handle = (line) => {
      if (!line) return;
      lines++;
      const asnMatch = /"ASN":(\d+)/.exec(line);
      if (!asnMatch || !wanted.has(Number(asnMatch[1]))) return;
      const o = JSON.parse(line);
      found.push({ cidr: o.CIDR, asn: o.ASN });
    };
    for await (const chunk of res.body) {
      buf += decoder.decode(chunk, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        handle(buf.slice(0, nl));
        buf = buf.slice(nl + 1);
      }
    }
    handle(buf);
    if (lines < 500000) throw new Error(`table looks truncated (${lines} lines)`);
    log(`bgp.tools: scanned ${lines} routes, ${found.length} matched`);
    return found;
  }, 2);
}

// RPKI VRPs (validated ROA payloads) for the given ASNs. Cloudflare's export first, rpki-client mirror second.
async function fetchRpki(wanted) {
  const urls = ['https://rpki.cloudflare.com/rpki.json', 'https://console.rpki-client.org/vrps.json'];
  let lastErr;
  for (const url of urls) {
    try {
      const text = await fetchText(`rpki ${new URL(url).host}`, url, 5 * 60 * 1000);
      const vrps = [];
      let total = 0;
      for (const m of text.matchAll(/\{[^{}]*"prefix"[^{}]*\}/g)) {
        total++;
        const o = JSON.parse(m[0]);
        const asn = Number(String(o.asn).replace(/^AS/i, ''));
        if (!wanted.has(asn)) continue;
        const p = parseCidr(o.prefix);
        if (p) vrps.push({ p, asn, maxLength: Number(o.maxLength ?? o.max_length ?? p.len) });
      }
      if (total < 100000) throw new Error(`only ${total} VRPs; export looks truncated`);
      log(`rpki (${new URL(url).host}): ${total} VRPs, ${vrps.length} for ByteDance ASNs`);
      return vrps;
    } catch (err) {
      lastErr = err;
      log(`rpki source ${url} failed: ${err.message}`);
    }
  }
  throw new SourceError(`rpki: all sources failed (${lastErr.message})`);
}

async function fetchCloudFeed(feed) {
  const out = []; // { cidr, service? }
  if (feed.provider === 'aws') {
    const j = await fetchJson('aws', feed.url);
    if (!Array.isArray(j.prefixes) || !Array.isArray(j.ipv6_prefixes)) throw new SourceError('aws: unexpected payload');
    for (const p of j.prefixes) out.push({ cidr: p.ip_prefix, service: p.service });
    for (const p of j.ipv6_prefixes) out.push({ cidr: p.ipv6_prefix, service: p.service });
  } else if (feed.provider === 'gcp') {
    const j = await fetchJson('gcp', feed.url);
    if (!Array.isArray(j.prefixes)) throw new SourceError('gcp: unexpected payload');
    for (const p of j.prefixes) out.push({ cidr: p.ipv4Prefix || p.ipv6Prefix });
  } else if (feed.provider === 'azure') {
    // The file name carries a weekly date; resolve the current one from Microsoft's download page.
    const page = await fetchText('azure download page', feed.url);
    const links = [...page.matchAll(/https:\/\/download\.microsoft\.com\/[^"'\s]*ServiceTags_Public_(\d{8})\.json/g)];
    if (!links.length) throw new SourceError('azure: ServiceTags_Public_*.json link not found on download page');
    const latest = links.sort((a, b) => b[1].localeCompare(a[1]))[0][0];
    log(`azure: using ${latest.split('/').pop()}`);
    const j = await fetchJson('azure', latest);
    if (!Array.isArray(j.values)) throw new SourceError('azure: unexpected payload');
    for (const v of j.values) for (const cidr of (v.properties && v.properties.addressPrefixes) || []) out.push({ cidr });
  }
  if (out.length < feed.min) throw new SourceError(`${feed.provider}: only ${out.length} prefixes (expected >= ${feed.min})`);
  log(`${feed.provider}: ${out.length} published prefixes`);
  return out;
}

async function fetchCrawlerSource(src) {
  const out = [];
  if (src.format === 'google-json') {
    const j = await fetchJson(src.source, src.url);
    if (!Array.isArray(j.prefixes)) throw new SourceError(`${src.source}: unexpected payload`);
    for (const p of j.prefixes) out.push(p.ipv4Prefix || p.ipv6Prefix);
  } else if (src.format === 'csv') {
    const text = await fetchText(src.source, src.url, 5 * 60 * 1000);
    for (const line of text.split('\n')) {
      const cidr = line.split(',')[0].trim();
      if (cidr) out.push(cidr);
    }
  } else {
    throw new SourceError(`${src.source}: unknown format ${src.format}`);
  }
  if (out.length === 0) throw new SourceError(`${src.source}: no prefixes`);
  log(`${src.source}: ${out.length} published prefixes`);
  return out;
}

// RIPE DB assignments registered to an organisation (inverse lookup on org:).
async function fetchRipeOrg(orgId) {
  const out = [];
  for (const type of ['inetnum', 'inet6num']) {
    const url = `https://rest.db.ripe.net/search.json?query-string=${encodeURIComponent(orgId)}` +
      `&inverse-attribute=org&type-filter=${type}&flags=no-referenced&flags=no-filtering`;
    const res = await withRetry(`ripe-db ${orgId} ${type}`, async () => {
      const r = await fetch(url, { headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' }, signal: AbortSignal.timeout(60000) });
      if (r.status === 404) return null; // RIPE DB answers 404 for "no entries"
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    });
    for (const o of (res && res.objects && res.objects.object) || []) out.push(o['primary-key'].attribute[0].value);
  }
  return out;
}

// RIPE DB inetnum/inet6num objects whose netname matches a pattern (full-text search, paged).
async function fetchRipeNetname(pattern) {
  const q = `(netname:${pattern}) AND (object-type:inetnum OR object-type:inet6num)`;
  const out = [];
  for (let start = 0, total = Infinity; start < total; start += 1000) {
    const url = 'https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select' +
      `?q=${encodeURIComponent(q)}&start=${start}&rows=1000&wt=json`;
    const j = await fetchJson(`ripe-db netname ${pattern}`, url);
    if (!j.result || !Array.isArray(j.result.docs)) throw new SourceError(`ripe-db netname ${pattern}: unexpected payload`);
    total = j.result.numFound;
    for (const d of j.result.docs) {
      const key = d.doc.strs.map((x) => x.str).find((x) => x.name === 'lookup-key');
      if (key) out.push(key.value);
    }
    if (j.result.docs.length === 0) break;
  }
  return out;
}

// "a.b.c.d - e.f.g.h" or a CIDR -> canonical prefixes
function ripeKeyToPrefixes(key) {
  const range = /^\s*(\S+)\s*-\s*(\S+)\s*$/.exec(key);
  if (range && net.isIPv4(range[1]) && net.isIPv4(range[2])) {
    const a = ipToBig(range[1], 4), b = ipToBig(range[2], 4);
    return a <= b ? rangeToPrefixes(4, a, b) : [];
  }
  const p = parseCidr(key);
  return p ? [p] : [];
}

function loadJsonFile(file, validate) {
  if (!fs.existsSync(file)) throw new SourceError(`${path.basename(file)} is missing`);
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!Array.isArray(data)) throw new SourceError(`${path.basename(file)} must be an array`);
  data.forEach((e, i) => validate(e, `${path.basename(file)}[${i}]`));
  return data;
}

function validateGroup(e, where) {
  if (!e || typeof e.provider !== 'string' || !CATEGORY_PRIORITY.hasOwnProperty(e.category) ||
      typeof e.tag !== 'string' || !e.tag) {
    throw new SourceError(`${where}: needs provider, a known category and tag`);
  }
  if (!e.asns && !e.ripe_org && !e.ripe_netname) throw new SourceError(`${where}: needs asns, ripe_org or ripe_netname`);
  if (e.asns && (!Array.isArray(e.asns) || !e.asns.every((a) => Number.isInteger(a) && a > 0))) {
    throw new SourceError(`${where}: asns must be positive integers`);
  }
}

function validateCrawler(e, where) {
  if (!e || typeof e.provider !== 'string' || !['crawler', 'relay'].includes(e.category) ||
      typeof e.tag !== 'string' || typeof e.url !== 'string' || typeof e.source !== 'string') {
    throw new SourceError(`${where}: needs provider, category (crawler|relay), tag, source and url`);
  }
}

function loadCurated() {
  if (!fs.existsSync(CURATED_FILE)) return [];
  const list = JSON.parse(fs.readFileSync(CURATED_FILE, 'utf8'));
  if (!Array.isArray(list)) throw new SourceError('known-usage.json must be an array');
  return list.map((e, i) => {
    if (!e || !parseCidr(e.prefix) || typeof e.tag !== 'string' || !e.tag ||
        typeof e.evidence !== 'string' || e.evidence.trim().length < 10) {
      throw new SourceError(`known-usage.json[${i}]: needs prefix, tag and an evidence string`);
    }
    return e;
  });
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

async function main() {
  const started = Date.now();
  const familyAsns = new Set(Object.keys(ASNS).map(Number));

  // --- network groups and ASN ownership (first layer wins) -----------------
  const vpnGroups = loadJsonFile(VPN_FILE, validateGroup);
  const dcGroups = loadJsonFile(DATACENTER_FILE, validateGroup);
  const crawlerSources = loadJsonFile(CRAWLER_FILE, validateCrawler);
  const curated = loadCurated();

  // Layer order decides who keeps an ASN listed twice: ByteDance > cloud > VPN > datacenter/proxy.
  const asnOwner = new Map(); // asn -> group
  const groups = [...CLOUD_ASN_GROUPS, ...vpnGroups, ...dcGroups];
  for (const g of groups) {
    g.asns = (g.asns || []).filter((asn) => {
      const owner = familyAsns.has(asn) ? 'bytedance' : asnOwner.get(asn)?.provider;
      if (owner) {
        log(`AS${asn} listed for ${g.provider} but already owned by ${owner}; keeping ${owner}`);
        return false;
      }
      asnOwner.set(asn, g);
      return true;
    });
  }
  const allAsns = new Set([...familyAsns, ...asnOwner.keys()]);

  // --- fetch everything in parallel (each host is only hit sequentially or through a small pool) -------
  const [apnic, radb, ripestatLists, bgptools, vrps, cloudFeeds, crawlerLists, ripeLists] = await Promise.all([
    fetchIrr('whois.apnic.net', 'apnic'),
    fetchIrr('whois.radb.net', 'radb'),
    pool([...allAsns], RIPESTAT_CONCURRENCY, async (asn) => ({ asn, list: await fetchRipestat(asn) })),
    SKIP_BGPTOOLS ? (log('bgp.tools skipped (SKIP_BGPTOOLS=1)'), Promise.resolve([])) : fetchBgptools(allAsns),
    fetchRpki(familyAsns),
    Promise.all(CLOUD_FEEDS.map(async (f) => ({ feed: f, list: await fetchCloudFeed(f) }))),
    Promise.all(crawlerSources.map(async (s) => ({ src: s, list: await fetchCrawlerSource(s) }))),
    pool(groups.filter((g) => g.ripe_org || g.ripe_netname), 2, async (g) => {
      const keys = g.ripe_org ? await fetchRipeOrg(g.ripe_org) : await fetchRipeNetname(g.ripe_netname);
      log(`ripe-db ${g.provider}: ${keys.length} objects`);
      return { group: g, keys };
    }),
  ]);
  if (!SKIP_BGPTOOLS && !bgptools.some((r) => familyAsns.has(r.asn))) {
    throw new SourceError('bgp.tools: no prefixes for any ByteDance ASN');
  }

  for (const { asn, list } of ripestatLists) {
    const who = ASNS[asn] ? 'bytedance' : asnOwner.get(asn).provider;
    log(`ripestat AS${asn} (${who}): ${list.length} announced prefixes`);
    if (ASNS[asn] && ASNS[asn].core && list.length === 0) {
      throw new SourceError(`ripestat AS${asn}: core ASN returned zero prefixes`);
    }
  }

  // ======================= ByteDance set (precision) =======================
  const BGP_SOURCES = new Set(['ripestat', 'bgptools']);
  const SOURCE_ORDER = ['ripestat', 'bgptools', 'apnic', 'radb', 'curated'];
  const byPrefix = new Map();
  let dropped = 0;

  const addBd = (cidr, asn, source, tag) => {
    const p = parseCidr(cidr);
    if (!p || !lengthOk(p)) { dropped++; return; }
    let e = byPrefix.get(p.cidr);
    if (!e) byPrefix.set(p.cidr, (e = { p, asns: new Set(), bgpAsns: new Set(), sources: new Set(), tag: null }));
    if (asn != null) e.asns.add(asn);
    if (asn != null && BGP_SOURCES.has(source)) e.bgpAsns.add(asn);
    e.sources.add(source);
    if (tag && !e.tag) e.tag = tag;
  };

  for (const { asn, list } of ripestatLists) if (ASNS[asn]) for (const cidr of list) addBd(cidr, asn, 'ripestat');
  for (const r of bgptools) if (familyAsns.has(r.asn)) addBd(r.cidr, r.asn, 'bgptools');
  for (const r of apnic) addBd(r.cidr, r.asn, 'apnic');
  for (const r of radb) addBd(r.cidr, r.asn, 'radb');
  for (const c of curated) addBd(c.prefix, c.asn ?? null, 'curated', c.tag);

  // RPKI: valid if a VRP for one of the prefix's origin ASNs covers it and allows its length.
  const vrpIndex = new PrefixIndex();
  for (const v of vrps) vrpIndex.add(v.p, v);
  const rpkiStatus = (e) => {
    const covering = vrpIndex.covering(e.p);
    if (!covering.length) return 'not-found';
    return covering.some((v) => e.asns.has(v.asn) && e.p.len <= v.maxLength) ? 'valid' : 'invalid';
  };

  let droppedPrecision = 0;
  const bdEntries = [];
  for (const e of byPrefix.values()) {
    e.rpki = rpkiStatus(e);
    e.announced = e.bgpAsns.size > 0;
    if (!e.announced && e.rpki !== 'valid' && !e.sources.has('curated')) { droppedPrecision++; continue; }
    bdEntries.push(e);
  }
  log(`bytedance: ${byPrefix.size} candidates, kept ${bdEntries.length} (announced or RPKI-valid), ` +
    `dropped ${droppedPrecision} IRR-only, ${dropped} invalid/out-of-range`);

  // ======================= Network set (recall) =======================
  const netMap = new Map(); // `${provider}|${cidr}` -> entry
  const providerInfo = new Map(); // provider -> { category, tag, holder, sources:Set }
  let netDropped = 0;

  const registerProvider = (g, source) => {
    if (!providerInfo.has(g.provider)) {
      providerInfo.set(g.provider, { category: g.category, tag: g.tag, holder: g.holder || g.provider, sources: new Set() });
    }
    const info = providerInfo.get(g.provider);
    if (info.category !== g.category || info.tag !== g.tag) {
      throw new SourceError(`provider ${g.provider} has conflicting category/tag definitions`);
    }
    info.sources.add(source);
  };

  const addNet = (p, g, source, extra = {}) => {
    if (!p || !lengthOk(p)) { netDropped++; return; }
    const key = `${g.provider}|${p.cidr}`;
    let e = netMap.get(key);
    if (!e) netMap.set(key, (e = { p, group: g, sources: new Set(), asns: new Set(), services: new Set() }));
    e.sources.add(source);
    if (extra.asn != null) e.asns.add(extra.asn);
    if (extra.service) e.services.add(extra.service);
  };

  for (const g of groups) if (g.asns.length || g.ripe_org || g.ripe_netname) registerProvider(g, g.asns.length ? 'bgp' : 'ripe-db');
  for (const { asn, list } of ripestatLists) {
    const g = asnOwner.get(asn);
    if (g) for (const cidr of list) addNet(parseCidr(cidr), g, 'ripestat', { asn });
  }
  for (const r of bgptools) {
    const g = asnOwner.get(r.asn);
    if (g) addNet(parseCidr(r.cidr), g, 'bgptools', { asn: r.asn });
  }
  for (const { group, keys } of ripeLists) {
    for (const key of keys) {
      const ps = ripeKeyToPrefixes(key);
      if (!ps.length) netDropped++;
      for (const p of ps) addNet(p, group, 'ripe-db');
    }
  }
  for (const { feed, list } of cloudFeeds) {
    registerProvider(feed, feed.source);
    for (const r of list) addNet(parseCidr(r.cidr), feed, feed.source, { service: r.service });
  }
  for (const { src, list } of crawlerLists) {
    registerProvider(src, src.source);
    let ps = list.map(parseCidr);
    netDropped += ps.filter((p) => !p).length;
    ps = ps.filter(Boolean);
    if (src.collapse) {
      const before = ps.length;
      ps = collapse(ps);
      log(`${src.source}: collapsed ${before} ranges into ${ps.length} CIDRs`);
    }
    for (const p of ps) addNet(p, src, src.source);
  }
  if (netDropped) log(`network set: dropped ${netDropped} malformed or out-of-range prefixes`);

  // Every provider must have produced something; an empty provider means a broken source.
  const providerCounts = {};
  for (const e of netMap.values()) providerCounts[e.group.provider] = (providerCounts[e.group.provider] || 0) + 1;
  for (const provider of providerInfo.keys()) {
    if (!providerCounts[provider]) throw new SourceError(`provider ${provider}: zero prefixes from all sources`);
  }

  // ======================= Cross-annotation (never merged) =======================
  const cloudIndex = new PrefixIndex();
  const bdIndex = new PrefixIndex();
  for (const e of netMap.values()) if (e.group.category === 'cloud') cloudIndex.add(e.p, e);
  for (const e of bdEntries) bdIndex.add(e.p, e);
  const cloudOverlap = new Map(); // bd entry -> cloud entries
  const noteOverlap = (bd, c) => {
    if (!cloudOverlap.has(bd)) cloudOverlap.set(bd, []);
    cloudOverlap.get(bd).push(c);
  };
  for (const bd of bdEntries) for (const c of cloudIndex.covering(bd.p)) noteOverlap(bd, c);
  for (const c of netMap.values()) {
    if (c.group.category !== 'cloud') continue;
    for (const bd of bdIndex.covering(c.p)) if (bd.p.len < c.p.len) noteOverlap(bd, c);
  }

  // ======================= Serialise =======================
  const SOURCE_RANK = (s) => { const i = SOURCE_ORDER.indexOf(s); return i < 0 ? 99 : i; };
  const prefixes = bdEntries.sort((a, b) => comparePrefixes(a.p, b.p)).map((e) => {
    const asns = [...e.asns].sort((a, b) => a - b);
    const asn = [...e.bgpAsns].sort((a, b) => a - b)[0] ?? asns[0] ?? null;
    const tag = e.tag || (asn != null && ASNS[asn] ? ASNS[asn].tag : 'bytedance');
    const sources = [...e.sources].sort((a, b) => SOURCE_RANK(a) - SOURCE_RANK(b));
    const out = {
      prefix: e.p.cidr,
      family: e.p.family === 4 ? 'ipv4' : 'ipv6',
      provider: asn != null && ASNS[asn] ? ASNS[asn].tag : 'bytedance',
      category: 'bytedance',
      tag,
      asn,
      source: sources[0],
      sources,
      announced: e.announced,
      rpki: e.rpki,
      strict: false,
    };
    if (asns.length > 1) out.asns = asns;
    const clouds = cloudOverlap.get(e);
    if (clouds) {
      const best = clouds.sort((a, b) => b.p.len - a.p.len || a.group.provider.localeCompare(b.group.provider))[0];
      out.cloud = { provider: best.group.provider, prefix: best.p.cidr };
    }
    // strict = matches live traffic: announced in BGP, hand-curated, or RPKI-valid ByteDance space that a
    // cloud announces/publishes (e.g. TikTok US routed by Oracle). RPKI-only subdivisions are not strict.
    out.strict = e.announced || e.sources.has('curated') || (e.rpki === 'valid' && !!clouds);
    return out;
  });

  const netPrefixes = [...netMap.values()]
    .sort((a, b) => comparePrefixes(a.p, b.p) || a.group.provider.localeCompare(b.group.provider))
    .map((e) => {
      const sources = [...e.sources].sort();
      const out = {
        prefix: e.p.cidr,
        family: e.p.family === 4 ? 'ipv4' : 'ipv6',
        provider: e.group.provider,
        category: e.group.category,
        tag: e.group.tag,
        source: sources[0],
        sources,
      };
      const asns = [...e.asns].sort((a, b) => a - b);
      if (asns.length) out.asn = asns[0];
      if (asns.length > 1) out.asns = asns;
      // AWS lists most ranges under both AMAZON and a specific service; keep the specific one.
      const services = [...e.services].filter((s) => s !== 'AMAZON').sort();
      if (services.length) out.service = services.join(',');
      return out;
    });

  // ======================= Sanity checks =======================
  if (prefixes.length < MIN_BYTEDANCE) {
    throw new SourceError(`only ${prefixes.length} ByteDance prefixes (minimum ${MIN_BYTEDANCE}); refusing to publish`);
  }
  const previous = fs.existsSync(FEED_FILE) ? JSON.parse(fs.readFileSync(FEED_FILE, 'utf8')) : null;
  if (previous && !ALLOW_SHRINK) {
    const checks = [['bytedance', previous.prefixes.length, prefixes.length]];
    const prevProviders = (previous.networks && previous.networks.providers) || {};
    for (const [prov, info] of Object.entries(prevProviders)) checks.push([prov, info.count, providerCounts[prov] || 0]);
    for (const [name, before, now] of checks) {
      if (now < before * (1 - MAX_SHRINK)) {
        throw new SourceError(`${name} shrank from ${before} to ${now} prefixes (>${MAX_SHRINK * 100}%); ` +
          'refusing to publish. Re-run with ALLOW_SHRINK=1 if this is genuine.');
      }
    }
  }

  // ======================= Write (only if content changed) =======================
  const contentHash = crypto.createHash('sha256')
    .update(`strict_announced=${STRICT_ANNOUNCED}\n`)
    .update(JSON.stringify(prefixes)).update('\n').update(JSON.stringify(netPrefixes)).digest('hex');
  if (previous && previous.content_hash === contentHash) {
    log(`unchanged (sha256 ${contentHash.slice(0, 12)}); nothing written (${((Date.now() - started) / 1000).toFixed(0)}s)`);
    return;
  }

  const netAsns = {};
  for (const [asn, g] of [...asnOwner].sort((a, b) => a[0] - b[0])) netAsns[asn] = { provider: g.provider, holder: g.holder };
  const providers = {};
  for (const [prov, info] of [...providerInfo].sort((a, b) => a[0].localeCompare(b[0]))) {
    providers[prov] = { category: info.category, tag: info.tag, holder: info.holder, count: providerCounts[prov], sources: [...info.sources].sort() };
  }

  const header = {
    schema_version: 2,
    generated_at: new Date().toISOString(),
    source: 'apnic+radb+ripestat+bgptools+rpki+aws+gcp+azure+ripe-db+crawler-feeds',
    content_hash: contentHash,
    prefix_count: prefixes.length,
    strict_count: prefixes.filter((p) => p.strict).length,
    strict_announced: STRICT_ANNOUNCED,
    asns: Object.fromEntries(Object.entries(ASNS).map(([a, v]) => [a, { provider: v.tag, holder: v.holder }])),
  };
  // One entry per line: diffable and ~half the size of fully pretty-printed JSON.
  const arr = (items, indent) => items.length
    ? '[\n' + items.map((x) => indent + '  ' + JSON.stringify(x)).join(',\n') + '\n' + indent + ']'
    : '[]';
  const json = '{\n' +
    Object.entries(header).map(([k, v]) => `  ${JSON.stringify(k)}: ${JSON.stringify(v)}`).join(',\n') + ',\n' +
    `  "prefixes": ${arr(prefixes, '  ')},\n` +
    '  "networks": {\n' +
    `    "prefix_count": ${netPrefixes.length},\n` +
    `    "asns": ${JSON.stringify(netAsns)},\n` +
    `    "providers": ${JSON.stringify(providers)},\n` +
    `    "prefixes": ${arr(netPrefixes, '    ')}\n` +
    '  }\n}\n';
  JSON.parse(json); // never write something we cannot read back

  // Flat file: "<cidr> <tag>", sorted (family, address, length, category priority). Identical CIDRs put
  // ByteDance first, then crawler > relay > vpn > proxy > cloud > hosting: consumers keep the first line.
  const flat = [
    ...prefixes.filter((e) => !STRICT_ANNOUNCED || e.strict).map((e) => ({ e, p: parseCidr(e.prefix) })),
    ...netPrefixes.map((e) => ({ e, p: parseCidr(e.prefix) })),
  ].sort((a, b) => comparePrefixes(a.p, b.p) ||
    CATEGORY_PRIORITY[a.e.category] - CATEGORY_PRIORITY[b.e.category] || a.e.provider.localeCompare(b.e.provider));
  const seen = new Set();
  const txtLines = [];
  for (const { e } of flat) {
    const line = `${e.prefix} ${e.tag}`;
    if (!seen.has(line)) { seen.add(line); txtLines.push(line); }
  }
  const txt = txtLines.join('\n') + '\n';

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const writeAtomic = (file, data) => {
    fs.writeFileSync(file + '.tmp', data);
    fs.renameSync(file + '.tmp', file);
  };
  // The current outputs were validated on their run, so they become last-good before being replaced.
  if (previous) {
    fs.copyFileSync(FEED_FILE, LASTGOOD_FILE);
    if (fs.existsSync(ALL_TXT_FILE)) fs.copyFileSync(ALL_TXT_FILE, ALL_TXT_LASTGOOD_FILE);
  }
  writeAtomic(FEED_FILE, json);
  writeAtomic(ALL_TXT_FILE, txt);
  if (!fs.existsSync(LASTGOOD_FILE)) fs.copyFileSync(FEED_FILE, LASTGOOD_FILE);
  if (!fs.existsSync(ALL_TXT_LASTGOOD_FILE)) fs.copyFileSync(ALL_TXT_FILE, ALL_TXT_LASTGOOD_FILE);

  const byCat = {};
  for (const e of netPrefixes) byCat[e.category] = (byCat[e.category] || 0) + 1;
  log(`wrote ${prefixes.length} ByteDance prefixes (${header.strict_count} strict` +
    `${STRICT_ANNOUNCED ? ', only those in feed.all.txt' : ''}; ${prefixes.filter((p) => p.cloud).length} overlap a cloud), ` +
    `${netPrefixes.length} network prefixes ${JSON.stringify(byCat)}, ${txtLines.length} lines in feed.all.txt, ` +
    `sha256 ${contentHash.slice(0, 12)} (${((Date.now() - started) / 1000).toFixed(0)}s)`);
}

main().catch((err) => {
  console.error(`::error::feed build failed: ${err.message}`);
  console.error('Existing feed files were left untouched.');
  process.exit(1);
});
