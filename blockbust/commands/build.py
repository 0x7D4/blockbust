"""
Build DNS censorship detection rules
"""

import argparse
import csv
import dns.resolver
import dns.message
import dns.query
import yaml
import random
import time
import requests
from collections import defaultdict, Counter
from typing import List, Dict, Set, Optional, Tuple
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

logger = logging.getLogger(__name__)

TRUSTED_RESOLVER = "8.8.8.8"
TRUSTED_DOH_URLS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query"
]
MAX_WORKERS = 10
STABILITY_CHECK_INTERVAL = 2  # seconds between checks


def get_legitimate_ips(
    domain: str, use_doh: bool = True, doh_urls: list = None
) -> Set[str]:
    """
    Fetch legitimate IPs for a domain and verify they are stable across multiple trusted resolvers.
    """
    if doh_urls is None:
        doh_urls = TRUSTED_DOH_URLS

    all_results = []
    providers = []

    logger.info(
        f"Verifying IP stability for {domain} across {len(doh_urls)} trusted DoH providers..."
    )

    for i, doh_url in enumerate(doh_urls):
        if i > 0:
            time.sleep(STABILITY_CHECK_INTERVAL)

        provider_name = (
            doh_url.split("//")[1]
            .split("/")[0]
            .replace("dns.", "")
            .replace(".net", "")
            .replace(".com", "")
        )
        providers.append(provider_name)

        try:
            if use_doh:
                ips = _query_doh(domain, doh_url)
            else:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [TRUSTED_RESOLVER]
                answers = resolver.resolve(domain, "A")
                ips = {answer.address for answer in answers}

            all_results.append(ips)
            logger.info(f"Check {i+1}/{len(doh_urls)} ({provider_name}): {sorted(ips)}")

        except Exception as e:
            logger.error(f"Error fetching IPs for {domain} from {provider_name}: {e}")
            raise

    # Check if IPs are stable across all queries
    unique_ip_sets = len(set(frozenset(result) for result in all_results))

    if unique_ip_sets > 1:
        logger.error(f"IP instability detected for {domain}!")
        logger.error(
            f"Observed {unique_ip_sets} different IP sets across {len(doh_urls)} providers:"
        )
        for i, (result, provider) in enumerate(zip(all_results, providers), 1):
            logger.error(f"  {provider}: {sorted(result)}")
        logger.error("")
        logger.error(
            "This domain has unstable IPs (likely due to load balancing or dynamic DNS)."
        )
        logger.error(
            "Please try using a different known-censored domain with stable IPs."
        )
        raise ValueError(
            f"Domain {domain} has unstable IPs - please use another censored domain"
        )

    # All queries returned the same set of IPs
    stable_ips = all_results[0]
    logger.info(
        f"All IPs stable across {len(doh_urls)} providers: {sorted(stable_ips)}"
    )

    return stable_ips


def _query_doh(domain: str, doh_url: str) -> Set[str]:
    """Query a domain using DNS over HTTPS."""
    try:
        if "dns.google" in doh_url:
            params = {"name": domain, "type": "A"}
            response = requests.get(doh_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            ips = set()
            if "Answer" in data:
                for answer in data["Answer"]:
                    if answer.get("type") == 1:  # Type 1 = A record
                        ips.add(answer["data"])
        else:
            query = dns.message.make_query(domain, "A")
            wire_data = query.to_wire()

            headers = {
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            }

            response = requests.post(
                doh_url, data=wire_data, headers=headers, timeout=10
            )
            response.raise_for_status()

            dns_response = dns.message.from_wire(response.content)

            ips = set()
            for answer in dns_response.answer:
                for item in answer.items:
                    if item.rdtype == dns.rdatatype.A:
                        ips.add(item.address)

        if not ips:
            raise Exception(f"No A records returned for {domain}")

        return ips

    except requests.RequestException as e:
        raise Exception(f"DoH query failed for {domain}: {e}")
    except Exception as e:
        raise Exception(f"DoH query failed for {domain}: {e}")


class RuleBuilder:
    def __init__(self, resolver_ip: str, test_domain: str, legitimate_ips: Set[str]):
        self.resolver_ip = resolver_ip
        self.test_domain = test_domain
        self.legitimate_ips = legitimate_ips
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [resolver_ip]
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

    def check_censorship(self) -> tuple[bool, Optional[Dict]]:
        try:
            logger.debug(f"Querying resolver {self.resolver_ip}")
            signatures = []

            try:
                a_answers = self.resolver.resolve(self.test_domain, "A")
                received_ips = {answer.address for answer in a_answers}

                if received_ips - self.legitimate_ips:
                    signatures.append(
                        {
                            "type": "A",
                            "pattern": list(received_ips)[0],
                        }
                    )
            except dns.resolver.NXDOMAIN:
                signatures.append(
                    {
                        "type": "NXDOMAIN",
                        "pattern": "domain_not_found",
                    }
                )
            except dns.resolver.NoAnswer:
                signatures.append(
                    {
                        "type": "NODATA",
                        "pattern": "no_answer",
                    }
                )

            if signatures:
                return True, signatures[0] if len(signatures) == 1 else signatures

        except Exception as e:
            logger.debug(f"Error querying resolver {self.resolver_ip}: {e}")
            return False, None

        return False, None


def read_resolver_list(filepath: str) -> Dict:
    groups = defaultdict(lambda: {"resolvers": {}, "name": "", "asn": ""})
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            handle = row["AS_Name"].split(" ")[0]

            key = (row["ASN"], handle)

            # Store full resolver metadata (use dict instead of set)
            resolver_data = {"ip": row["ip"]}

            # Only add metadata if non-empty
            if row.get("reverse_dns"):
                resolver_data["reverse_dns"] = row["reverse_dns"]
            if row.get("chaos_hostname"):
                resolver_data["chaos_hostname"] = row["chaos_hostname"]
            if row.get("chaos_version"):
                resolver_data["chaos_version"] = row["chaos_version"]
            if row.get("chaos_id"):
                resolver_data["chaos_id"] = row["chaos_id"]
            groups[key]["resolvers"][row["ip"]] = resolver_data
            groups[key]["name"] = row["AS_Name"]
            groups[key]["asn"] = row["ASN"]
    return groups


def generate_config_file(
    name: str,
    asn: str,
    resolvers: Dict,
    test_domain: str,
    legitimate_ips: Set[str],
    max_resolvers: Optional[int] = None,
) -> dict:
    network_name = name.split(" ", 1)[1] if " " in name else name
    signature_groups = defaultdict(list)

    if max_resolvers and len(resolvers) > max_resolvers:
        resolver_ips = list(resolvers.keys())
        sampled_ips = random.sample(resolver_ips, max_resolvers)
        resolvers = {ip: resolvers[ip] for ip in sampled_ips}

    def check_resolver(resolver_ip):
        detector = RuleBuilder(resolver_ip, test_domain, legitimate_ips)
        is_censorious, signature = detector.check_censorship()
        return resolvers[resolver_ip], is_censorious, signature

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(check_resolver, resolver_ip)
            for resolver_ip in resolvers.keys()
        ]

        for future in tqdm(
            as_completed(futures),
            total=len(resolvers),
            desc=f"Testing {name} resolvers",
            position=1,
            leave=False
        ):
            resolver, is_censorious, signature = future.result()
            if is_censorious and signature:
                if isinstance(signature, list):
                    for sig in signature:
                        key = (sig["type"], sig["pattern"])
                        signature_groups[key].append(resolver)
                else:
                    key = (signature["type"], signature["pattern"])
                    signature_groups[key].append(resolver)

    sorted_signatures = sorted(
        signature_groups.items(), key=lambda x: len(x[1]), reverse=True
    )

    formatted_signatures = []
    for i, ((sig_type, pattern), resolver_list) in enumerate(sorted_signatures):
        sig_name = "primary" if i == 0 else f"alt{i}"
        # Remove duplicates by IP, keep metadata
        unique_resolvers = {r["ip"]: r for r in resolver_list}.values()
        formatted_signatures.append(
            {
                "pattern": pattern,
                "type": sig_type,
                "name": sig_name,
                "resolvers": sorted(list(unique_resolvers), key=lambda x: x["ip"]),
            }
        )

    return {
        "network_info": {
            "name": network_name,
            "asn": int(asn),
            "signatures": formatted_signatures,
        }
    }


def process_network(
    asn: str,
    handle: str,
    info: Dict,
    test_domain: str,
    legitimate_ips: Set[str],
    max_resolvers: Optional[int] = None,
) -> Optional[Tuple[str, dict]]:
    tqdm.write(f"Processing AS{asn} ({info['name']})")

    result = generate_config_file(
        info["name"], asn, info["resolvers"], test_domain, legitimate_ips, max_resolvers
    )

    if result["network_info"]["signatures"]:
        return handle, result
    return None


def build_rules(
    input_file, domain, output_dir="rules", max_resolvers=None, use_doh=True
):
    """Build censorship detection rules from resolver list"""

    legitimate_ips = get_legitimate_ips(domain, use_doh=use_doh)

    logger.info(f"Using test domain: {domain}")
    logger.info(f"Legitimate IPs: {legitimate_ips}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    try:
        groups = read_resolver_list(input_file)

        with tqdm(total=len(groups), desc="Processing networks", position=0) as pbar:
            for (asn, handle), info in groups.items():
                result = process_network(
                    asn, handle, info, domain, legitimate_ips, max_resolvers
                )
                if result:
                    handle, config = result
                    output_file = output_path / f"{handle.lower()}-{asn}.yaml"
                    with open(output_file, "w") as f:
                        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
                    tqdm.write(f"Generated config for {handle}")
                pbar.update(1)

        return 0

    except Exception as e:
        logger.error(f"Error processing resolvers: {e}")
        return 1


def register_parser(subparsers):
    """Register the build-rules subcommand"""
    parser = subparsers.add_parser(
        "build-rules",
        help="Build censorship detection rules from validated resolvers",
        description="""
Query resolvers against a known-censored domain to identify DNS manipulation patterns.

Creates YAML rule files in rules/ directory organized by network (ASN).
Each rule file contains censorship signatures and the resolvers that exhibit them.
Supports A record poisoning, NXDOMAIN blocking, and NODATA responses.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Input CSV file containing resolver list (with ASN enrichment)",
    )

    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Domain to test for DNS manipulation (e.g., thepiratebay.org)",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default="rules",
        help="Output directory for YAML rule files (default: rules)",
    )

    parser.add_argument(
        "--max-resolvers", type=int, help="Maximum number of resolvers to test per ASN"
    )

    parser.add_argument(
        "--no-doh",
        dest="use_doh",
        action="store_false",
        help="Disable DNS over HTTPS and use standard DNS instead",
    )

    parser.set_defaults(
        func=lambda args: build_rules(
            args.input, args.domain, args.output_dir, args.max_resolvers, args.use_doh
        )
    )
