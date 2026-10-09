# IP classification feed

An auto-refreshing feed that answers one question for any incoming IP: **what network is this, and how
sure are we?** It covers:

- **ByteDance** (ByteDance, TikTok, Volcengine, BytePlus, Lark): built for precision.
- **Cloud** (AWS, GCP, Azure, Alibaba, Oracle), **hosting** (DigitalOcean, Hetzner, OVH, …),
  **VPN** (NordVPN, Mullvad, ProtonVPN), **proxy** (IPRoyal, Bright Data, Oxylabs),
  **crawlers** (Googlebot, Bingbot, Applebot) and **iCloud Private Relay**: built for recall.

It's built for **traffic analytics**, and rebuilt daily from authoritative sources by a GitHub Action.
A full build takes under a minute.

## What this does and does not catch

| Visitor | Caught? | Notes |
|---|---|---|
| ByteDance crawlers (Bytespider), link-preview fetchers, backends | **Yes**, category `bytedance` | |
| Bots / scripts on AWS, GCP, Azure, DigitalOcean, Hetzner, … | **Yes**, `cloud` / `hosting` | The provider owns the IP; the visitor is its customer |
| VPN users (NordVPN, Mullvad, ProtonVPN) | **Yes**, `vpn` | Only providers with their own ASN (see below) |
| Commercial proxy datacenter IPs | **Partly**, `proxy` | Residential proxies use real home IPs and cannot be caught by IP |
| Googlebot / Bingbot / Applebot | **Yes**, `crawler` | Confirm the User-Agent matches |
| Safari users with iCloud Private Relay | **Yes**, `relay` | Real people, location hidden |
| A person who opens your link inside the TikTok app | **No**: they arrive from their own ISP IP | User-Agent contains e.g. `BytedanceWebview`, `musical_ly`, `trill`; Referer `tiktok.com` |

## Files

| File | Contents |
|---|---|
| `feed.all.txt` | **The file downstream loads.** Every prefix from every layer: `<cidr> <tag>`, one per line. |
| `bytedance-feed.json` | The structured record: ByteDance set + network set with all fields (schema below). |
| `bytedance-feed.lastgood.json`, `feed.all.lastgood.txt` | The previous validated outputs, for rollback. |
| `build-feed.js` | The pipeline. Zero dependencies, Node ≥ 18. |
| `lookup.js` | Lookups, `explain` mode, and access-log classification. |
| `datacenter-asns.json` | Input: hosting / cloud / proxy networks. |
| `vpn-asns.json` | Input: VPN networks. |
| `crawler-prefixes.json` | Input: published crawler and relay range files. |
| `known-usage.json` | Input: hand-curated ByteDance prefixes (each needs an `evidence` string). Starts empty. |
| `.github/workflows/refresh-feed.yml` | Daily refresh + commit-on-change. |

## `feed.all.txt`

```
1.0.0.0/24 datacenter
3.80.0.0/12 aws
40.77.167.0/24 crawler
40.77.167.0/24 azure
71.18.252.0/24 tiktok
172.224.226.0/26 private-relay
```

- **Sorting:** lines are sorted by family, address and prefix length, so diffs stay stable.
- **Canonical CIDRs:** host bits are zeroed and IPv6 uses RFC 5952 notation. IPv4 /8–/32 and IPv6 /16–/128 only.
- **Overlaps stay distinct.** A ByteDance prefix inside Oracle space, or a Bingbot range inside Azure, keeps
  one line per provider.
- **Identical CIDRs:** when the same CIDR appears under several providers, the lines are ordered by category
  priority: `bytedance` > `crawler` > `relay` > `vpn` > `proxy` > `cloud` > `hosting`. A loader that keeps
  the first line per CIDR gets the most specific meaning. A loader that keeps the last line gets the most
  generic one. Pick deliberately.
- **Nesting:** a longest-prefix trie returns the most specific network, e.g. a Private Relay /26 inside a
  Cloudflare /24 (e.g. `104.28.28.0/26` inside `104.28.28.0/24`).

Column 2 (`tag`) values:

| Category | Tags |
|---|---|
| bytedance | `bytedance`, `tiktok`, `volcengine`, `byteplus`, `lark` (plus any tag from `known-usage.json`) |
| cloud | `aws`, `gcp`, `azure`, `alibaba`, `oracle` |
| hosting | `datacenter` |
| proxy | `proxy` |
| vpn | `vpn` |
| crawler | `crawler` |
| relay | `private-relay` |

## Layers and sources

### ByteDance set: precision

ASNs (holder names verified via RIPEstat, 2026-10-09):

| ASN | Holder | Provider |
|---|---|---|
| AS396986 | Bytedance Inc. | `bytedance` |
| AS137775 | Beijing Bytedance Network Technology Co., Ltd. | `bytedance` |
| AS138699 | TIKTOK PTE. LTD. | `tiktok` |
| AS11983 | Tiktok U.S. Data Security Inc. | `tiktok` |
| AS137718 | Beijing Volcano Engine Technology Co., Ltd. | `volcengine` |
| AS150436 | Byteplus Pte. Ltd. | `byteplus` |
| AS398175 | Lark Enterprise Applications Inc. | `lark` |

Candidate prefixes come from four sources:
1. **APNIC whois** route objects.
2. **RADB** route objects.
3. **RIPEstat** `announced-prefixes`.
4. **bgp.tools** live table.

A candidate is **emitted only if**:
- it is **announced in BGP** by a ByteDance ASN, or
- it is **RPKI-valid**: a ROA from the address holder authorises that ASN for that prefix length.
  ROAs come from Cloudflare's RPKI export, with the rpki-client mirror as fallback.

IRR-only entries with no RPKI backing are dropped. Entries in `known-usage.json` are always kept.

Note that most RPKI-valid-but-unannounced entries are Volcengine. It pre-registers every subdivision of its
blocks and covers them with wide-`maxLength` ROAs. Those prefixes are authorised and ByteDance-owned, but
not visible in global BGP; they may be unused or routed only inside China. `explain` reports them with
`medium` confidence.

### Network set: recall

Everything the providers publish is emitted. These entries are **never merged** into the ByteDance set.

| Provider(s) | Category | Source |
|---|---|---|
| AWS | cloud | `ip-ranges.amazonaws.com/ip-ranges.json` (v4 + v6; `service` kept, e.g. `EC2`, `CLOUDFRONT`) |
| GCP | cloud | `gstatic.com/ipranges/cloud.json` |
| Azure | cloud | `ServiceTags_Public_YYYYMMDD.json`. The current file name is resolved from Microsoft's download page each run. All service tags are deduped into one set. |
| Alibaba | cloud | BGP announcements of AS45102, AS37963, AS24429, AS134963 (no official range file exists) |
| `datacenter-asns.json` | hosting / cloud / proxy | BGP announcements (RIPEstat + bgp.tools) per ASN; RIPE DB for Bright Data / Oxylabs |
| `vpn-asns.json` | vpn | BGP announcements per ASN |
| `crawler-prefixes.json` | crawler / relay | Official published range files |

#### `datacenter-asns.json` / `vpn-asns.json`

An array of network groups:

```json
{ "provider": "cloudflare", "category": "hosting", "tag": "datacenter",
  "holder": "Cloudflare, Inc.", "asns": [13335, 209242] }
```

- `provider`: a specific name. It becomes the `provider` field and must be unique per category/tag.
- `category`: one of `bytedance`, `cloud`, `hosting`, `vpn`, `proxy`, `crawler`, `relay`.
- `tag`: column 2 of `feed.all.txt`.
- One source is required:
  - `asns`: the announced prefixes of each ASN.
  - `ripe_org`: every `inetnum` / `inet6num` registered to that RIPE organisation.
  - `ripe_netname`: every RIPE `inetnum` / `inet6num` whose netname matches the pattern (full-text search).
- **ASN dedupe across layers:** an ASN listed twice is kept by the first owner in the order ByteDance → cloud
  (Alibaba) → `vpn-asns.json` → `datacenter-asns.json`. The build logs a line when this happens.

Notes on the current lists:

- **Oracle (AS31898)** is categorised `cloud` with tag `oracle`, consistent with the other clouds.
- **Vultr** is AS20473 only. AS64515 is a private-use ASN (64512–65534) and never appears in public BGP.
- **NordVPN** is AS136787 (PacketHub S.A., Nord Security's network). AS212238 is *Datacamp Limited*
  (CDN77). NordVPN rents from Datacamp, but so do many others, so it sits in hosting as `datacamp`.
- **ExpressVPN** is not listed. Its company's ASN (AS218960, Express Technologies Ltd) announces nothing.
  ExpressVPN servers run on rented space, largely M247 (covered as hosting).
- **Mullvad** is AS216025 and AS197141. AS39351 (31173 Services AB) is a separate hosting company that
  Mullvad uses. AS57138 is only Mullvad's DNS-over-HTTPS service.
- **ProtonVPN** is AS209103 and AS199218 (ProtonVPN), plus AS62371 (Proton AG, which also carries Mail).
  AS198953 "Proton66 OOO" is an unrelated company.
- **Bright Data and Oxylabs have no ASN.** Bright Data is covered by the RIPE organisation `ORG-LNL29-RIPE`
  (7 blocks). Oxylabs is covered by RIPE netname `OXYLABS*` (~3,400 assignments, mostly inside Hetzner).
  Both have `medium` confidence: these are registry assignments, not routing data. Residential proxy
  traffic from these companies is undetectable by IP.

#### `crawler-prefixes.json`

An array of published range files:

```json
{ "provider": "google", "category": "crawler", "tag": "crawler", "holder": "Google LLC (Googlebot)",
  "source": "googlebot", "format": "google-json",
  "url": "https://developers.google.com/static/search/apis/ipranges/googlebot.json" }
```

- `format` is either `google-json` (a `{"prefixes":[{"ipv4Prefix"|"ipv6Prefix"}]}` file) or `csv`
  (CIDR in the first column).
- `collapse: true` merges adjacent and overlapping ranges into the minimal CIDR set.
- **Included:**
  - Googlebot, Google special crawlers and Google user-triggered fetchers.
  - Bingbot and Applebot.
  - Apple iCloud Private Relay egress, collapsed from ~285k city-level ranges to ~14k CIDRs. The city
    data is dropped.

BGPView (`api.bgpview.io`) is not used: it has shut down and its domain no longer resolves.

## JSON schema (`bytedance-feed.json`, `schema_version: 2`)

```jsonc
{
  "schema_version": 2,
  "generated_at": "2026-10-09T04:58:56.296Z",
  "source": "apnic+radb+ripestat+bgptools+rpki+aws+gcp+azure+ripe-db+crawler-feeds",
  "content_hash": "sha256 of both prefix arrays",
  "prefix_count": 13052,
  "asns": { "138699": { "provider": "tiktok", "holder": "TIKTOK PTE. LTD." } },
  "prefixes": [   // ByteDance set
    { "prefix": "71.18.252.0/24", "family": "ipv4", "provider": "tiktok", "category": "bytedance",
      "tag": "tiktok", "asn": 138699, "source": "ripestat", "sources": ["ripestat", "bgptools", "radb"],
      "announced": true, "rpki": "valid" }
  ],
  "networks": {   // network set, kept separate
    "prefix_count": 127398,
    "asns": { "24940": { "provider": "hetzner", "holder": "Hetzner Online GmbH" } },
    "providers": { "aws": { "category": "cloud", "tag": "aws", "holder": "Amazon Web Services",
                            "count": 11330, "sources": ["aws"] } },
    "prefixes": [
      { "prefix": "3.80.0.0/12", "family": "ipv4", "provider": "aws", "category": "cloud", "tag": "aws",
        "source": "aws", "sources": ["aws"], "service": "EC2" }
    ]
  }
}
```

Every entry has `prefix`, `family`, `provider`, `category`, `tag`, `source` and `sources`. Some fields
depend on the set:

- **ByteDance entries:**
  - `asn` is the BGP origin if the prefix is announced, otherwise the IRR origin. `asns` appears when
    several ASNs claim the prefix.
  - `announced` is `true` or `false`. `rpki` is `valid`, `invalid` or `not-found`.
  - `cloud` (optional) gives the most specific cloud prefix it overlaps, e.g.
    `{ "provider": "oracle", "prefix": "139.177.229.0/24" }`. That example is ByteDance-registered,
    RPKI-authorised space that Oracle announces, which fits TikTok US running on Oracle Cloud.
- **Network entries:**
  - `asn` is present when the entry came from BGP.
  - `service` is present for AWS entries.

The JSON has one entry per line (~23 MB). Use it for the structured record and use `feed.all.txt` for loading.

## Lookups

### `explain`: everything known about an IP

```bash
node lookup.js explain 71.18.252.10 1.93.4.1 3.80.0.1 8.8.8.8
```

This prints one JSON line per IP on **stdout** and a short human-readable summary on **stderr**:

```json
{"ip":"71.18.252.10","match":{"prefix":"71.18.252.0/24","provider":"tiktok","category":"bytedance","tag":"tiktok","asn":138699,"holder":"TIKTOK PTE. LTD.","announced":true,"sources":["ripestat","bgptools","radb"],"rpki":"valid"},"confidence":"high","reason":"announced in BGP by AS138699 and RPKI-valid","note":"ByteDance-operated network (…)","also":[{"prefix":"71.18.0.0/16","provider":"bytedance","category":"bytedance"}]}
```

```
71.18.252.10: 71.18.252.0/24 · tiktok AS138699 (TIKTOK PTE. LTD.) · bytedance · announced, RPKI valid · sources ripestat,bgptools,radb · confidence high: announced in BGP by AS138699 and RPKI-valid
    also inside: 71.18.0.0/16 bytedance/bytedance
```

**Output fields:**
- `match` is the most specific matching entry, or `null`.
- `also` lists every other entry covering the IP.
- `announced` is `null` for entries from published feeds (AWS, crawlers, RIPE DB), since those aren't
  checked against BGP.
- `confidence` is `high`, `medium` or `none`, and `reason` explains why.

**How confidence is decided:**

| Confidence | When |
|---|---|
| high | Announced in BGP by the network's own ASN, or published by the provider itself (AWS / GCP / Azure / Google / Bing / Apple files) |
| medium | ByteDance prefix that is RPKI-authorised but not announced; announced but RPKI-invalid; hand-curated; RIPE DB assignments (Bright Data, Oxylabs) |
| none | No layer matched |

Run `cat ips.txt | node lookup.js explain` to do the same for one IP per line.

### Other modes

To print one tab-separated line per IP:

```bash
node lookup.js 71.18.252.10 2a01:4f8::1
```

To classify the first IP on each line of a log and print totals by category and provider:

```bash
cat /var/log/nginx/access.log | node lookup.js
```

## Running the build

```bash
node build-feed.js
```

All sources are fetched in parallel. Each host is only hit sequentially or through a small pool: whois
1.5 s apart, and RIPEstat with 4 requests at a time. A full run takes 45–60 s locally. Downloads are about
50 MB (bgp.tools), 106 MB (RPKI), 12 MB (Private Relay) and 4 MB (Azure). Nothing is cached between runs.

Environment variables:

- `SKIP_BGPTOOLS=1`: skip bgp.tools (RIPEstat still supplies BGP data).
- `ALLOW_SHRINK=1`: accept a > 30 % drop in any provider.
- `FEED_OUT_DIR=…`: write output somewhere else.
- `FEED_CONTACT=…`: contact URL/email sent in the User-Agent.

## Failure behaviour

The build fails with a non-zero exit and **writes nothing** when:

- any source fails. That covers whois, RIPEstat, bgp.tools, RPKI (both mirrors), AWS / GCP / Azure, the
  RIPE DB and every crawler/relay file. It fails on timeout, HTTP errors after retries, or a malformed
  payload. A cloud or hosting source being down is a failure, never a skip;
- a whois server returns an error banner (e.g. APNIC `%ERROR:201: access denied`);
- a core ByteDance ASN (396986, 138699, 137718, 150436) has zero announced prefixes;
- any provider ends up with zero prefixes, or a cloud feed is below its minimum (AWS / Azure 1,000, GCP 100);
- the bgp.tools table (< 500k routes) or RPKI export (< 100k VRPs) looks truncated;
- the ByteDance set has fewer than 100 prefixes;
- the ByteDance set or **any provider** shrank by more than 30 % vs. the committed feed.

Files are written atomically (temp file + rename), and the JSON is re-parsed before writing. On a change,
the current outputs are copied to the `lastgood` files first. If the content hash is unchanged, nothing is
written and the workflow makes no commit. A failed scheduled run shows as a red run in Actions, and GitHub
emails you.

## Deploying

The workflow runs daily at 04:17 UTC and can be started manually from **Actions → Refresh IP
classification feed → Run workflow**. It declares `contents: write` itself, so no repository setting is
needed.

To consume the feed, use `https://raw.githubusercontent.com/<owner>/<repo>/main/feed.all.txt`. For a
private repository, that URL needs a token. GitHub disables scheduled workflows in public repositories
after 60 days without activity; re-enable it from the Actions tab if that happens.

## Verifying a prefix is genuinely ByteDance-owned

The feed records **who registered or announces** a prefix, not who sends traffic from it. To check one:

1. **RIR registration.** The block should be registered to a ByteDance entity.
   - ARIN space: `whois -h whois.arin.net "n + 71.18.252.0"` shows `OrgName: Bytedance Inc.`
   - APNIC space: use RDAP, e.g. `https://rdap.apnic.net/ip/101.126.24.0` shows `VOLCANO-ENGINE`.
2. **Current origin.**
   `https://stat.ripe.net/data/prefix-overview/data.json?resource=71.18.252.0/24`
3. **RPKI.** `valid` means the address holder cryptographically authorised that ASN:
   `https://stat.ripe.net/data/rpki-validation/data.json?resource=AS138699&prefix=71.18.252.0/24`
4. **Visibility and upstreams:** `https://bgp.tools/prefix/71.18.252.0/24`

How to read the result:

- **Steps 1–3 all agree:** owned and operated by ByteDance.
- **`announced: false, rpki: valid`:** authorised by the holder but not routed globally right now.
- **`volcengine` / `byteplus`:** ByteDance's cloud. The traffic may come from a cloud *customer*.
- **A `cloud` field:** the prefix also overlaps a cloud provider's announcement or published range. That
  means either ByteDance space routed through that cloud, or ByteDance renting from it.
- **Several origins (`asns`) or RPKI `invalid`:** treat as suspect (possible leak or hijack).

## Adding known rented ranges

Add entries to `known-usage.json` only with public evidence, such as a ByteDance document, a published
crawler list or reproducible reverse DNS:

```json
[
  { "prefix": "203.0.113.0/24", "tag": "bytedance-suspected", "asn": 45102,
    "evidence": "URL or description of how this was confirmed, and the date" }
]
```

- The build refuses entries that have no `evidence` string.
- Curated entries skip the announced/RPKI precision filter.
- Use a distinct tag such as `bytedance-suspected` so these entries stay separable from registry and
  BGP data.
