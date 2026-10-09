#!/usr/bin/env node
// Builds bytedance-feed.json from IRR whois (APNIC + RADB), RIPEstat and bgp.tools.
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

// Cloud providers ByteDance is known to rent from. Their prefixes are NOT added to the feed;
// they are only used to annotate feed prefixes that overlap them.
const CLOUD_ASNS = {
  45102: 'alibaba',
  37963: 'alibaba',
  24429: 'alibaba',
  134963: 'alibaba',
};

const OUT_DIR = process.env.FEED_OUT_DIR || __dirname;
const FEED_FILE = path.join(OUT_DIR, 'bytedance-feed.json');
const LASTGOOD_FILE = path.join(OUT_DIR, 'bytedance-feed.lastgood.json');
const TXT_FILE = path.join(OUT_DIR, 'bytedance-feed.txt');
const TXT_ANNOUNCED_FILE = path.join(OUT_DIR, 'bytedance-feed.announced.txt');
const CURATED_FILE = path.join(__dirname, 'known-usage.json');

const MIN_TOTAL = 100; // fewer prefixes than this means something upstream broke
const MAX_SHRINK = 0.3; // fail if the feed shrinks by more than 30% vs. the current one
const SKIP_BGPTOOLS = process.env.SKIP_BGPTOOLS === '1';
const ALLOW_SHRINK = process.env.ALLOW_SHRINK === '1';

const CONTACT = process.env.FEED_CONTACT ||
  (process.env.GITHUB_REPOSITORY ? `https://github.com/${process.env.GITHUB_REPOSITORY}` : 'local run');
const USER_AGENT = `bytedance-ip-feed/1.0 (+${CONTACT})`;

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

async function fetchChecked(url, timeoutMs) {
  const res = await fetch(url, {
    headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
  if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status}`), { fatal: true });
  return res;
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

function parseCidr(str) {
  const m = /^\s*([0-9a-fA-F:.]+)\/(\d{1,3})\s*$/.exec(String(str));
  if (!m) return null;
  const family = net.isIPv4(m[1]) ? 4 : net.isIPv6(m[1]) ? 6 : 0;
  if (!family) return null;
  const bits = family === 4 ? 32 : 128;
  const len = Number(m[2]);
  if (len > bits) return null;
  const host = (1n << BigInt(bits - len)) - 1n;
  const raw = ipToBig(m[1], family);
  const start = raw & ~host & ((1n << BigInt(bits)) - 1n);
  return { family, len, start, end: start | host, cidr: `${bigToIp(start, family)}/${len}`, hostBitsSet: start !== raw };
}

// Keep IPv4 /8../32 and IPv6 /16../128.
function lengthOk(p) {
  return p.family === 4 ? p.len >= 8 && p.len <= 32 : p.len >= 16 && p.len <= 128;
}

const overlaps = (a, b) => a.family === b.family && a.start <= b.end && b.start <= a.end;

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
  return withRetry(`ripestat AS${asn}`, async () => {
    const res = await fetchChecked(url, 60000);
    const j = await res.json();
    if (j.status !== 'ok' || !j.data || !Array.isArray(j.data.prefixes)) {
      throw new Error(`unexpected payload (status=${j.status})`);
    }
    return j.data.prefixes.map((p) => p.prefix);
  });
}

// bgp.tools full table: one JSON object per line, {"CIDR","ASN","Hits"}. Streamed, ~1M lines.
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
  const familyAsns = new Set(Object.keys(ASNS).map(Number));
  const cloudAsns = new Set(Object.keys(CLOUD_ASNS).map(Number));

  // Sequential on purpose: whois servers and RIPEstat both rate-limit per client IP.
  const apnic = await fetchIrr('whois.apnic.net', 'apnic');
  const radb = await fetchIrr('whois.radb.net', 'radb');

  const ripestat = [];
  for (const asn of familyAsns) {
    const list = await fetchRipestat(asn);
    log(`ripestat AS${asn}: ${list.length} announced prefixes`);
    if (ASNS[asn].core && list.length === 0) {
      throw new SourceError(`ripestat AS${asn}: core ASN returned zero prefixes`);
    }
    for (const cidr of list) ripestat.push({ cidr, asn });
  }

  const cloudPrefixes = [];
  for (const asn of cloudAsns) {
    const list = await fetchRipestat(asn);
    log(`ripestat AS${asn} (${CLOUD_ASNS[asn]}): ${list.length} announced prefixes`);
    if (list.length === 0) throw new SourceError(`ripestat AS${asn}: cloud ASN returned zero prefixes`);
    for (const cidr of list) cloudPrefixes.push({ p: parseCidr(cidr), asn, provider: CLOUD_ASNS[asn] });
  }

  let bgptools = [];
  if (SKIP_BGPTOOLS) {
    log('bgp.tools skipped (SKIP_BGPTOOLS=1)');
  } else {
    const all = await fetchBgptools(new Set([...familyAsns, ...cloudAsns]));
    bgptools = all.filter((r) => familyAsns.has(r.asn));
    for (const r of all.filter((r) => cloudAsns.has(r.asn))) {
      cloudPrefixes.push({ p: parseCidr(r.cidr), asn: r.asn, provider: CLOUD_ASNS[r.asn] });
    }
    if (bgptools.length === 0) throw new SourceError('bgp.tools: no prefixes for any ByteDance ASN');
  }

  const curated = loadCurated();

  // --- merge ---------------------------------------------------------------
  const BGP_SOURCES = new Set(['ripestat', 'bgptools']);
  const SOURCE_ORDER = ['ripestat', 'bgptools', 'apnic', 'radb', 'curated'];
  const byPrefix = new Map();
  let dropped = 0;

  const add = (cidr, asn, source, tag) => {
    const p = parseCidr(cidr);
    if (!p || !lengthOk(p)) { dropped++; return; }
    if (p.hostBitsSet) log(`normalised ${cidr} -> ${p.cidr} (${source})`);
    let e = byPrefix.get(p.cidr);
    if (!e) byPrefix.set(p.cidr, (e = { p, asns: new Set(), bgpAsns: new Set(), sources: new Set(), tag: null }));
    if (asn != null) e.asns.add(asn);
    if (asn != null && BGP_SOURCES.has(source)) e.bgpAsns.add(asn);
    e.sources.add(source);
    if (tag && !e.tag) e.tag = tag;
  };

  for (const r of ripestat) add(r.cidr, r.asn, 'ripestat');
  for (const r of bgptools) add(r.cidr, r.asn, 'bgptools');
  for (const r of apnic) add(r.cidr, r.asn, 'apnic');
  for (const r of radb) add(r.cidr, r.asn, 'radb');
  for (const c of curated) add(c.prefix, c.asn ?? null, 'curated', c.tag);
  if (dropped) log(`dropped ${dropped} invalid or out-of-range prefixes`);

  const prefixes = [...byPrefix.values()]
    .sort((a, b) => a.p.family - b.p.family || (a.p.start < b.p.start ? -1 : a.p.start > b.p.start ? 1 : a.p.len - b.p.len))
    .map((e) => {
      const asns = [...e.asns].sort((a, b) => a - b);
      const asn = [...e.bgpAsns].sort((a, b) => a - b)[0] ?? asns[0] ?? null;
      const sources = SOURCE_ORDER.filter((s) => e.sources.has(s));
      const out = {
        prefix: e.p.cidr,
        family: e.p.family === 4 ? 'ipv4' : 'ipv6',
        asn,
        tag: e.tag || (asn != null && ASNS[asn] ? ASNS[asn].tag : 'bytedance'),
        source: sources[0],
        sources,
        announced: e.bgpAsns.size > 0,
      };
      if (asns.length > 1) out.asns = asns;
      const clouds = cloudPrefixes.filter((c) => c.p && overlaps(c.p, e.p));
      if (clouds.length) {
        const best = clouds.sort((a, b) => b.p.len - a.p.len)[0];
        out.cloud = { provider: best.provider, asn: best.asn, prefix: best.p.cidr };
      }
      return out;
    });

  // --- sanity checks -------------------------------------------------------
  if (prefixes.length < MIN_TOTAL) {
    throw new SourceError(`only ${prefixes.length} prefixes (minimum ${MIN_TOTAL}); refusing to publish`);
  }
  const previous = fs.existsSync(FEED_FILE) ? JSON.parse(fs.readFileSync(FEED_FILE, 'utf8')) : null;
  if (previous && !ALLOW_SHRINK) {
    const prevCount = previous.prefixes.length;
    if (prefixes.length < prevCount * (1 - MAX_SHRINK)) {
      throw new SourceError(`feed shrank from ${prevCount} to ${prefixes.length} (>${MAX_SHRINK * 100}%); ` +
        'refusing to publish. Re-run with ALLOW_SHRINK=1 if this is genuine.');
    }
  }

  // --- write (only if content changed) -------------------------------------
  const contentHash = crypto.createHash('sha256').update(JSON.stringify(prefixes)).digest('hex');
  if (previous && previous.content_hash === contentHash) {
    log(`unchanged (${prefixes.length} prefixes, sha256 ${contentHash.slice(0, 12)}); nothing written`);
    return;
  }

  const feed = {
    generated_at: new Date().toISOString(),
    source: 'apnic+radb+ripestat+bgptools',
    content_hash: contentHash,
    prefix_count: prefixes.length,
    asns: Object.fromEntries(Object.entries(ASNS).map(([a, v]) => [a, { tag: v.tag, holder: v.holder }])),
    prefixes,
  };

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const writeAtomic = (file, data) => {
    fs.writeFileSync(file + '.tmp', data);
    fs.renameSync(file + '.tmp', file);
  };
  // The current feed was validated on its run, so it becomes last-good before being replaced.
  if (previous) fs.copyFileSync(FEED_FILE, LASTGOOD_FILE);
  writeAtomic(FEED_FILE, JSON.stringify(feed, null, 2) + '\n');
  writeAtomic(TXT_FILE, prefixes.map((p) => p.prefix).join('\n') + '\n');
  writeAtomic(TXT_ANNOUNCED_FILE, prefixes.filter((p) => p.announced).map((p) => p.prefix).join('\n') + '\n');
  if (!previous) fs.copyFileSync(FEED_FILE, LASTGOOD_FILE);

  const v4 = prefixes.filter((p) => p.family === 'ipv4').length;
  log(`wrote ${prefixes.length} prefixes (${v4} IPv4, ${prefixes.length - v4} IPv6), ` +
    `${prefixes.filter((p) => p.cloud).length} overlapping cloud ranges, sha256 ${contentHash.slice(0, 12)}`);
}

main().catch((err) => {
  console.error(`::error::bytedance feed build failed: ${err.message}`);
  console.error('Existing feed files were left untouched.');
  process.exit(1);
});
