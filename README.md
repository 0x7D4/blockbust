# blockbust

Command-line wrapper around ZDNS with censorship detection utilities

blockbust identifies DNS censorship by testing domains against resolvers from different networks. It validates resolvers, builds detection rules from known-censored domains, and scans at scale using ZDNS.

## Requirements

- Python 3.7+
- [ZDNS](https://github.com/zmap/zdns?tab=readme-ov-file#install)

## Installation

```bash
git clone https://github.com/qurbat/blockbust
cd blockbust
pip install .
```

## Quick start

```bash
# 1. Validate and enrich resolver list
blockbust validate resolvers.txt example.com -o validated.csv

# 2. Build censorship detection rules using a known-blocked domain
blockbust build-rules -i validated.csv -d thepiratebay.org

# 3. Detect censorship across your domain list
blockbust detect --input domains.txt --rule rules/network-12345.yaml --verify 8.8.8.8
```

## Commands

### `blockbust validate`

Validates DNS resolvers and enriches them with metadata.

```bash
blockbust validate <resolvers-file> <test-domain> [options]
```

- Tests each resolver against a baseline domain (e.g., example.com) for correctness
- Performs reverse DNS lookups and queries CHAOS TXT records
- Enriches with ASN and AS name data

**Important:** Test domain must have static, non-GEO-DNS records. Use simple domains with stable A records like `example.com`.

**Common options:**
- `-o, --output` - Output CSV file path
- `--skip-chaos` - Skip CHAOS record queries

### `blockbust build-rules`

Builds detection rules from validated resolvers.

```bash
blockbust build-rules -i <validated-csv> -d <domain> [options]
```

- Queries a known-censored domain against all resolvers
- Groups resolvers by ASN and blocking signature
- Generates YAML rule files in `rules/` directory
- Supports multiple signature types per network (forged IPs, `NXDOMAIN`, etc.)

**Common options:**
- `-i, --input` - Input CSV file (from validate command)
- `-d, --domain` - Known-censored domain to test (e.g. `thepiratebay.org`)
- `-o, --output-dir` - Output directory (default: rules)
- `--max-resolvers` - Limit resolvers tested per ASN

### `blockbust detect`

Uses ZDNS to send queries and detect censorship using rule files.

```bash
blockbust detect --input <domains-file> --rule <rule-file> [options]
```

- Uses ZDNS for high-speed parallel DNS queries
- Matches responses against blocking signatures
- Optionally verifies matches with a trusted resolver
- Outputs matched domains and query statistics

**Common options:**
- `--input` - File containing domains to test (one per line)
- `--rule` - Path to YAML rule file
- `--verify` - Trusted resolver for verification (e.g., 8.8.8.8)
- `--threads` - Number of ZDNS threads (default: 1000)
- `--cached` - Use existing jsonl output instead of re-querying

## Workflow details

Rule files are YAML format containing:

- **Network information**: Name, ASN(s)
- **Blocking signatures**: IP addresses or patterns (NXDOMAIN, NODATA)
- **Resolver lists**: IPs exhibiting each signature

**Signature types:**
- **A record poisoning**: Returns forged IP instead of legitimate address
- **NXDOMAIN blocking**: Returns NXDOMAIN for existing domains (pattern: `domain_not_found`)
- **NODATA blocking**: Returns empty response (pattern: `no_answer`)

The `--verify` flag is recommended for:

- Bogon IP patterns like `127.0.0.1`, `0.0.0.0` that may legitimately exist
- NXDOMAIN responses, to distinguish from legitimately non-existent domains
- NODATA responses, to confirm domains should have A records

Matched domains are cross-checked with a trusted resolver (e.g., 8.8.8.8); only domains that resolve differently are flagged as censored.

## Rule format specification

```yaml
network_info:
  name: <Network Name>, <Country Code>
  asn: <ASN number>
  signatures:
  - pattern: <IP address | "domain_not_found" | "no_answer">
    type: <A | NXDOMAIN | NODATA>
    name: <primary | alt1 | alt2>
    resolvers:
    - ip: <resolver IP>
      reverse_dns: <PTR record>
      chaos_hostname: <hostname.bind result>
      chaos_version: <version.bind result>
      chaos_id: <id.server result>
```