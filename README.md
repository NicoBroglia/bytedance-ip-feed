# ByteDance IP feed

An auto-refreshing list of IP prefixes belonging to ByteDance-family networks (ByteDance, TikTok,
Volcengine, BytePlus, Lark). Built from public routing registries and live BGP data, for **traffic
analytics**: finding out how much of your site's traffic comes from ByteDance infrastructure.

There is no official feed. This one is rebuilt daily from authoritative sources by a GitHub Action.

## What this does and does not catch

| Visitor | Caught by this feed? | How to detect it instead |
|---|---|---|
| ByteDance crawlers (Bytespider etc.), link-preview fetchers, scanners | **Yes** — they run on ByteDance / Volcengine / BytePlus networks | — |
| Anything hosted by a Volcengine / BytePlus cloud customer | **Yes**, tagged `volcengine` / `byteplus` (note: may not be ByteDance itself) | — |
| A person who opens your link inside the TikTok / Douyin / Lark app | **No** — they connect from their own ISP or mobile IP | User-Agent contains e.g. `BytedanceWebview`, `musical_ly`, `trill`, `ByteLocale`; Referer from `tiktok.com` |
| ByteDance services running on rented third-party cloud (AWS, Alibaba, Oracle…) | Only if listed in `known-usage.json` | — |

For a full picture, combine the IP lookup with User-Agent / Referer matching in your analytics.

## Files

| File | Contents |
|---|---|
| `build-feed.js` | The pipeline. Zero dependencies, Node ≥ 18. |
| `lookup.js` | Longest-prefix-match lookup / access-log classifier using the feed. |
| `known-usage.json` | Hand-curated extra prefixes (each must carry an `evidence` string). Starts empty. |
| `bytedance-feed.json` | The feed (schema below). |
| `bytedance-feed.lastgood.json` | The previous validated feed — roll back to this if a new one looks wrong. |
| `bytedance-feed.txt` | One CIDR per line, all prefixes. |
| `bytedance-feed.announced.txt` | One CIDR per line, only prefixes currently seen in BGP (higher confidence). |
| `.github/workflows/refresh-feed.yml` | Daily refresh + commit-on-change. |

## Sources

ASNs (holder names verified via RIPEstat on 2026-10-09; re-verify when adding new ones):

| ASN | Holder | Tag |
|---|---|---|
| AS396986 | Bytedance Inc. | `bytedance` |
| AS137775 | Beijing Bytedance Network Technology Co., Ltd. | `bytedance` |
| AS138699 | TIKTOK PTE. LTD. | `tiktok` |
| AS11983 | Tiktok U.S. Data Security Inc. | `tiktok` |
| AS137718 | Beijing Volcano Engine Technology Co., Ltd. | `volcengine` |
| AS150436 | Byteplus Pte. Ltd. | `byteplus` |
| AS398175 | Lark Enterprise Applications Inc. | `lark` |

For each ASN the pipeline pulls:

1. **APNIC whois** (`whois.apnic.net`, `-i origin ASxxx`): registered route objects.
2. **RADB** (`whois.radb.net`): route objects mirrored from all major IRRs (ARIN, RIPE, APNIC…).
3. **RIPEstat** `announced-prefixes`: what is actually announced in BGP (last 2 weeks, RIS collectors).
4. **bgp.tools** `table.jsonl`: second, independent view of the live BGP table.

Then **cloud enrichment**: announced prefixes of Alibaba Cloud ASNs (AS45102, AS37963, AS24429, AS134963)
are fetched. They are **never added** to the feed. A feed prefix that overlaps one gets a `cloud` field.
(Alibaba publishes no machine-readable range list, so its BGP announcements are the authoritative proxy.)

Note: BGPView (`api.bgpview.io`) is not used. It has shut down and no longer resolves.

## Schema

```json
{
  "generated_at": "2026-10-09T04:17:00.000Z",
  "source": "apnic+radb+ripestat+bgptools",
  "content_hash": "sha256 of the prefixes array",
  "prefix_count": 21587,
  "asns": { "138699": { "tag": "tiktok", "holder": "TIKTOK PTE. LTD." } },
  "prefixes": [
    {
      "prefix": "71.18.252.0/24",
      "family": "ipv4",
      "asn": 138699,
      "tag": "tiktok",
      "source": "ripestat",
      "sources": ["ripestat", "bgptools", "apnic", "radb"],
      "announced": true
    }
  ]
}
```

- `prefix` is a canonical CIDR string (host bits zeroed, IPv6 RFC 5952), loadable straight into a CIDR trie.
- `asn` is the BGP origin when announced, otherwise the IRR origin. `asns` appears only when several ASNs claim the prefix.
- `source` is the strongest source; `sources` lists all that reported it (BGP sources first).
- `announced: false` means the prefix is registered in an IRR but not visible in global BGP right now
  (reserved space, or routed only inside China where public collectors can't see it). Lower confidence.
- `cloud` (optional): `{ "provider": "alibaba", "asn": 45102, "prefix": "…" }` — overlaps a rented-cloud range.
- Prefixes are sorted (family, address, length) so diffs are stable. IPv4 /8–/32 and IPv6 /16–/128 only.

## Running locally

```bash
node build-feed.js
```

Takes a few minutes (whois is throttled to ~1 query / 1.5 s; the bgp.tools table is ~50 MB).
Environment variables:

- `SKIP_BGPTOOLS=1`: skip the bgp.tools download (faster local runs).
- `ALLOW_SHRINK=1`: accept a > 30 % drop in prefix count.
- `FEED_OUT_DIR=…`: write output somewhere else.
- `FEED_CONTACT=…`: contact URL/email sent in the User-Agent (bgp.tools asks for one).

Look up IPs, or classify an access log:

```bash
node lookup.js 71.18.252.10 2605:340:f027::5
```

```bash
cat /var/log/nginx/access.log | node lookup.js
```

## Failure behaviour

The build fails with a non-zero exit and **writes nothing** when:

- any source times out, returns HTTP errors after retries, or returns a malformed payload;
- a whois server returns an error banner (e.g. APNIC `%ERROR:201: access denied` from rate limiting);
- a core ASN (396986, 138699, 137718, 150436) has zero announced prefixes, or a cloud ASN returns none;
- the bgp.tools table looks truncated (< 500k routes);
- the feed has fewer than 100 prefixes, or shrank by more than 30 % vs. the committed one.

Files are written atomically (temp file + rename). On a successful change, the previous feed is copied to
`bytedance-feed.lastgood.json` first. If the prefix hash is unchanged, nothing is written, so there is
no commit. A failed scheduled run shows as a red run in Actions and GitHub emails you.

## Deploying

1. Push these files to a GitHub repo.
2. In **Settings → Actions → General → Workflow permissions**, allow read and write.
3. Run the workflow once manually (**Actions → Refresh ByteDance IP feed → Run workflow**).
4. Consume the feed from the raw URL:
   `https://raw.githubusercontent.com/<you>/<repo>/main/bytedance-feed.json`

GitHub disables scheduled workflows in public repos after 60 days without repository activity.
If the prefixes don't change for that long, re-enable the workflow from the Actions tab.

## Verifying a prefix is genuinely ByteDance-owned

The feed records **who registered or announces** a prefix, not who sends traffic from it.
Before trusting a specific prefix, check:

1. **Who allocates it (RIR registration).** The network block should be registered to a ByteDance entity.
   ```bash
   whois -h whois.arin.net "n + 71.18.252.0"
   ```
   (shows `OrgName: Bytedance Inc.`). For APNIC space, use RDAP: `https://rdap.apnic.net/ip/101.126.24.0`
   (shows `VOLCANO-ENGINE`, Beijing Volcano Engine Technology).
2. **Who announces it now.** The BGP origin should be one of the ASNs above:
   `https://stat.ripe.net/data/prefix-overview/data.json?resource=71.18.252.0/24`
3. **RPKI.** A `valid` result means the address holder cryptographically authorised that ASN to originate it,
   which is the strongest single signal:
   `https://stat.ripe.net/data/rpki-validation/data.json?resource=AS138699&prefix=71.18.252.0/24`
4. **Cross-check visibility** on https://bgp.tools/prefix/71.18.252.0/24 (upstreams, other origins).

How to read the result:

- Steps 1–3 all agree → owned and operated by ByteDance.
- `announced: false` → registered intent only; it was never confirmed in live BGP.
- Tag `volcengine` / `byteplus` → owned by ByteDance's cloud, but the traffic may come from a cloud *customer*.
- `cloud` field present → the space belongs to that cloud provider, and ByteDance is at most a tenant.
- Several origins (`asns`) or an RPKI `invalid` → treat as suspect (possible leak or hijack).

## Adding known rented ranges

Add entries to `known-usage.json` only with public evidence (a ByteDance doc, a published crawler IP
list, reproducible reverse DNS, etc.):

```json
[
  { "prefix": "203.0.113.0/24", "tag": "bytedance-suspected", "asn": 45102,
    "evidence": "URL or description of how this was confirmed, and the date" }
]
```

The build refuses entries without an `evidence` string. Use a distinct tag (e.g. `bytedance-suspected`) so
these entries stay separable from registry and BGP data.
