#!/usr/bin/env node
// Longest-prefix lookup against bytedance-feed.json.
//   node lookup.js 71.18.252.10 2605:340::1
//   cat access.log | node lookup.js            (first IP on each line; prints matches + summary)
'use strict';

const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const feedPath = process.env.FEED || path.join(__dirname, 'bytedance-feed.json');
const feed = JSON.parse(fs.readFileSync(feedPath, 'utf8'));

function toBits(ip) {
  if (net.isIPv4(ip)) return ip.split('.').map((o) => Number(o).toString(2).padStart(8, '0')).join('');
  if (!net.isIPv6(ip)) return null;
  let s = ip.replace(/%.*$/, '');
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const b = toBits(v4[1]);
    s = s.slice(0, -v4[1].length) + parseInt(b.slice(0, 16), 2).toString(16) + ':' + parseInt(b.slice(16), 2).toString(16);
  }
  const [h, t] = s.split('::');
  const hg = h ? h.split(':') : [];
  const tg = t !== undefined && t ? t.split(':') : [];
  const groups = t !== undefined ? [...hg, ...Array(8 - hg.length - tg.length).fill('0'), ...tg] : hg;
  return groups.map((g) => parseInt(g, 16).toString(2).padStart(16, '0')).join('');
}

// One binary trie per family; each node: [child0, child1, entry]
const roots = { 4: [null, null, null], 6: [null, null, null] };
for (const entry of feed.prefixes) {
  const [ip, len] = entry.prefix.split('/');
  const bits = toBits(ip);
  let node = roots[net.isIPv4(ip) ? 4 : 6];
  for (let i = 0; i < Number(len); i++) {
    const b = bits.charCodeAt(i) - 48;
    node = node[b] || (node[b] = [null, null, null]);
  }
  node[2] = entry;
}

function lookup(ip) {
  const bits = toBits(ip);
  if (!bits) return null;
  let node = roots[net.isIPv4(ip) ? 4 : 6], best = node[2];
  for (let i = 0; node && i < bits.length; i++) {
    node = node[bits.charCodeAt(i) - 48];
    if (node && node[2]) best = node[2];
  }
  return best;
}

function report(ip, m) {
  if (!m) return;
  const cloud = m.cloud ? ` cloud=${m.cloud.provider}` : '';
  console.log(`${ip}\t${m.prefix}\tAS${m.asn}\t${m.tag}\tannounced=${m.announced}${cloud}`);
}

if (process.argv.length > 2) {
  for (const ip of process.argv.slice(2)) {
    const m = lookup(ip);
    m ? report(ip, m) : console.log(`${ip}\t-`);
  }
} else {
  const ipRe = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:.]+)/;
  const counts = new Map();
  let total = 0, buf = '';
  const handle = (line) => {
    const m = ipRe.exec(line);
    if (!m || !net.isIP(m[1])) return;
    total++;
    const hit = lookup(m[1]);
    if (!hit) return;
    report(m[1], hit);
    counts.set(hit.tag, (counts.get(hit.tag) || 0) + 1);
  };
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (d) => {
    buf += d;
    const lines = buf.split('\n');
    buf = lines.pop();
    lines.forEach(handle);
  });
  process.stdin.on('end', () => {
    handle(buf);
    const hits = [...counts.values()].reduce((a, b) => a + b, 0);
    console.error(`\n${hits}/${total} requests from ByteDance-family networks`);
    for (const [tag, n] of [...counts].sort((a, b) => b[1] - a[1])) console.error(`  ${tag}: ${n}`);
  });
}
