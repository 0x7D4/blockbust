"""
Validate DNS resolvers with integrated setup and enrichment
"""

import argparse
import concurrent.futures
import dns.resolver
import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass
import dns.reversename
from typing import List, Optional, Dict, Tuple
import ipaddress
import time
from pathlib import Path
import logging
from dataclasses import dataclass
import socket
import sys
from tqdm import tqdm
import csv
import json
import os
import gzip
from datetime import datetime

import requests
from bs4 import BeautifulSoup

import pyasn

DEFAULT_PFX2AS_URL = (
    "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as"
)
DEFAULT_OUTPUT_DIR = "data"


@dataclass
class DNSResult:
    ip: str
    is_expected: bool
    duration: float
    hostname: Optional[str] = None
    error: Optional[str] = None


def read_dns_servers(filename: str) -> List[str]:
    with open(filename) as f:
        return [line.strip() for line in f if line.strip()]


def get_baseline(domain: str) -> List[str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
    resolver.timeout = 2
    try:
        answers = resolver.resolve(domain, "A")
        return sorted([str(rdata) for rdata in answers])
    except dns.exception.DNSException as e:
        raise Exception(f"Baseline query failed: {e}")


def get_reverse_dns(ip: str) -> Optional[str]:
    try:
        reverse_ip = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
        resolver.timeout = 1
        resolver.lifetime = 1
        answers = resolver.resolve(reverse_ip, "PTR")
        return str(answers[0].target).rstrip(".")
    except (dns.exception.DNSException, ValueError):
        return None


def query_dns(server: str, domain: str, expected: List[str]) -> DNSResult:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.timeout = 1
    resolver.lifetime = 1

    start_time = time.time()
    try:
        answers = resolver.resolve(domain, "A")
        duration = round((time.time() - start_time) * 1000)
        actual = sorted([str(rdata) for rdata in answers])
        return DNSResult(server, actual == expected, duration, None)
    except (dns.exception.DNSException, socket.error) as e:
        return DNSResult(
            server, False, round((time.time() - start_time) * 1000), None, str(e)
        )
    finally:
        resolver.reset()


def process_batch(
    servers: List[str], domain: str, expected: List[str], max_workers: int = 20
) -> List[DNSResult]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(query_dns, server, domain, expected) for server in servers
        ]
        for future in tqdm(
            concurrent.futures.as_completed(futures),
            total=len(futures),
            desc="Processing batch",
            leave=False,
        ):
            try:
                result = future.result()
                if result.error is None:
                    results.append(result)
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
    return results


def query_chaos_txt(ip: str, qname: str, timeout: float = 2.0) -> Optional[str]:
    """Query CHAOS TXT record (hostname.bind, version.bind, id.server)"""
    try:
        query = dns.message.make_query(qname, dns.rdatatype.TXT, dns.rdataclass.CHAOS)
        response = dns.query.tcp(query, ip, timeout=timeout)

        for answer in response.answer:
            for item in answer.items:
                if item.rdtype == dns.rdatatype.TXT:
                    return b"".join(item.strings).decode("utf-8", errors="ignore")
        return None
    except Exception:
        return None


def get_latest_pfx2as_file(base_url: str, year: int, month: int) -> str:
    """Get the latest pfx2as file from CAIDA for a given year/month"""
    url = f"{base_url}/{year}/{month:02d}/"

    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        raise Exception(f"Failed to fetch directory listing from {url}: {e}")

    soup = BeautifulSoup(response.text, "html.parser")

    entries = []
    for line in soup.get_text().split("\n"):
        if "routeviews-rv2-" in line and ".pfx2as.gz" in line:
            parts = line.split()
            if len(parts) >= 2:
                filename = parts[0]
                try:
                    date_str = parts[1]
                    date = datetime.strptime(date_str, "%Y-%m-%d")
                    entries.append((filename, date))
                except (ValueError, IndexError):
                    continue

    if not entries:
        raise Exception(f"No pfx2as files found at {url}")

    latest_file = max(entries, key=lambda x: x[1])[0]
    return url + latest_file


def download_and_extract(url: str, output_dir: str) -> str:
    """Download and extract a gzipped file"""
    filename = os.path.basename(url)
    gz_path = os.path.join(output_dir, filename)

    logging.info(f"Downloading {url}...")

    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()

        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0

        with open(gz_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                if total_size:
                    progress = (downloaded / total_size) * 100
                    print(f"\rDownload progress: {progress:.1f}%", end="", flush=True)

        print()
        logging.info(f"Downloaded to {gz_path}")

    except requests.RequestException as e:
        if os.path.exists(gz_path):
            os.remove(gz_path)
        raise Exception(f"Download failed: {e}")

    output_file = gz_path[:-3]
    logging.info(f"Extracting to {output_file}...")

    try:
        with gzip.open(gz_path, "rb") as f_in:
            with open(output_file, "wb") as f_out:
                f_out.write(f_in.read())
    except Exception as e:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise Exception(f"Extraction failed: {e}")
    finally:
        if os.path.exists(gz_path):
            os.remove(gz_path)

    return output_file


def process_pfx2as_file(input_file: str, output_file: str):
    """Convert pfx2as format to pyasn-compatible format"""
    logging.info(f"Processing {input_file}...")

    output_lines = []
    with open(input_file) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 3:
                ip, mask, asn = parts[0], parts[1], parts[2]
                output_lines.append(f"{ip}/{mask}\t{asn}")

    with open(output_file, "w") as f:
        f.write("\n".join(output_lines))

    logging.info(f"Created pyasn database: {output_file}")

    if os.path.exists(input_file):
        os.remove(input_file)


def download_asnames(output_file: str):
    """Download AS names file"""
    logging.info("Downloading AS names...")

    try:
        import subprocess

        result = subprocess.run(
            ["pyasn_util_asnames.py", "-o", output_file], capture_output=True, text=True
        )
        if result.returncode == 0:
            logging.info(f"AS names written to {output_file}")
            return 0
        else:
            logging.warning(f"pyasn_util_asnames.py failed: {result.stderr}")
            logging.info(
                "You may need to run: pyasn_util_asnames.py -o data/asnames.json manually"
            )
            return 1
    except FileNotFoundError:
        logging.warning("pyasn_util_asnames.py not found")
        logging.info("Please run: pyasn_util_asnames.py -o data/asnames.json manually")
        return 1


def setup_asn_databases(
    output_dir: str = DEFAULT_OUTPUT_DIR, year: int = None, month: int = None
):
    """Download and setup ASN database files from CAIDA"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    if year is None:
        year = now.year
    if month is None:
        month = now.month

    try:
        logging.info(f"Fetching latest pfx2as file for {year}-{month:02d}...")
        pfx2as_url = get_latest_pfx2as_file(DEFAULT_PFX2AS_URL, year, month)

        extracted_file = download_and_extract(pfx2as_url, output_dir)

        output_db = os.path.join(output_dir, "ipasn.db")
        process_pfx2as_file(extracted_file, output_db)

        logging.info(f"IP-ASN database ready: {output_db}")

        asnames_file = os.path.join(output_dir, "asnames.json")
        download_asnames(asnames_file)

        logging.info("Setup complete")
        return 0

    except Exception as e:
        logging.error(f"Setup failed: {e}")
        return 1


MAX_DB_AGE_DAYS = 30


def ensure_databases(
    ipasn_db=None,
    asnames_file=None,
    setup_output_dir=DEFAULT_OUTPUT_DIR,
    setup_year=None,
    setup_month=None,
    skip_enrich=False,
):
    """Check if databases exist and are fresh, run setup if missing or stale"""
    if skip_enrich:
        return

    if ipasn_db is None:
        ipasn_db = os.path.join(setup_output_dir, "ipasn.db")
    if asnames_file is None:
        asnames_file = os.path.join(setup_output_dir, "asnames.json")

    db_path = Path(ipasn_db)
    names_path = Path(asnames_file)

    if not db_path.exists() or not names_path.exists():
        logging.info("ASN databases not found. Running setup...")
        result = setup_asn_databases(setup_output_dir, setup_year, setup_month)
        if result != 0:
            raise Exception("Failed to setup ASN databases")
        return

    # Check staleness based on file modification time
    db_age_days = (time.time() - db_path.stat().st_mtime) / 86400
    if db_age_days > MAX_DB_AGE_DAYS:
        logging.warning(
            f"ASN database is {int(db_age_days)} days old (threshold: {MAX_DB_AGE_DAYS} days). Refreshing..."
        )
        result = setup_asn_databases(setup_output_dir, setup_year, setup_month)
        if result != 0:
            raise Exception("Failed to refresh ASN databases")


def load_asn_databases(ipasn_db: str, asnames_file: str):
    """Load ASN databases for enrichment"""
    try:
        asndb = pyasn.pyasn(ipasn_db)
    except Exception as e:
        raise ValueError(f"Error loading IP-ASN database from {ipasn_db}: {e}")

    try:
        with open(asnames_file) as f:
            asnames = json.load(f)
    except Exception as e:
        raise ValueError(f"Error loading AS names file from {asnames_file}: {e}")

    return asndb, asnames


def ip2asn(ip: str, asndb) -> Optional[int]:
    """Get ASN for an IP address"""
    try:
        asn = asndb.lookup(ip)[0]
        return asn
    except:
        return None


def asn2name(asn: Optional[int], asnames: Dict) -> Optional[str]:
    """Get AS name for an ASN"""
    if not asn:
        return None
    return asnames.get(str(asn))


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved (RFC 1918, link-local, etc.)"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def ipinfo_lookup(ip: str) -> Tuple[Optional[int], Optional[str]]:
    """Fallback: query ipinfo.io for ASN/org info (works for private gateways via their public IP).
    
    For private IPs (e.g. 192.168.29.1), ipinfo.io uses the caller's public IP,
    returning the ISP info for the network the gateway is on.
    For public IPs that pyasn couldn't resolve, queries that specific IP.
    
    Returns (asn_number, as_name) or (None, None) on failure.
    """
    try:
        # For private IPs, query without IP to get the caller's public IP info
        # For public IPs, query that specific IP
        if is_private_ip(ip):
            url = "https://ipinfo.io/json"
        else:
            url = f"https://ipinfo.io/{ip}/json"
        
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        
        org = data.get("org", "")
        if org and org.startswith("AS"):
            # org format: "AS15169 Google LLC"
            parts = org.split(" ", 1)
            asn_str = parts[0][2:]  # strip "AS" prefix
            asn = int(asn_str)
            as_name = parts[1] if len(parts) > 1 else ""
            return asn, as_name
        
        return None, None
    except Exception as e:
        logging.debug(f"ipinfo lookup failed for {ip}: {e}")
        return None, None


def validate_resolvers(
    servers_file,
    domain,
    output=None,
    batch_size=100,
    skip_enrich=False,
    skip_reverse_dns=False,
    skip_chaos=False,
    ipasn_db=None,
    asnames_file=None,
    setup_output_dir=DEFAULT_OUTPUT_DIR,
    setup_year=None,
    setup_month=None,
):
    """Validate DNS resolvers with integrated setup, DNS queries, and ASN enrichment"""
    if output is None:
        output = f"validated_resolvers_{int(time.time())}.csv"

    try:
        # Ensure databases exist (auto-run setup if needed)
        if not skip_enrich:
            logging.info("Ensuring ASN databases are available...")
            ensure_databases(
                ipasn_db,
                asnames_file,
                setup_output_dir,
                setup_year,
                setup_month,
                skip_enrich,
            )

            # Set default paths if not provided
            if ipasn_db is None:
                ipasn_db = os.path.join(setup_output_dir, "ipasn.db")
            if asnames_file is None:
                asnames_file = os.path.join(setup_output_dir, "asnames.json")

            # Load ASN databases
            asndb, asnames = load_asn_databases(ipasn_db, asnames_file)
            logging.info("ASN databases loaded successfully")

        logging.info("Validating DNS resolvers...")
        expected = get_baseline(domain)
        logging.info(f"Baseline response for {domain}: {expected}")

        servers = read_dns_servers(servers_file)
        logging.info(f"Testing {len(servers)} DNS servers")

        # Collect validated resolvers
        validated_resolvers = []

        total_batches = (len(servers) + batch_size - 1) // batch_size
        for i in tqdm(
            range(0, len(servers), batch_size),
            total=total_batches,
            desc="Validating resolvers",
        ):
            batch = servers[i : i + batch_size]
            results = process_batch(batch, domain, expected)

            for result in results:
                if not result.error and result.is_expected:
                    validated_resolvers.append(
                        {"ip": result.ip, "rtt_ms": result.duration}
                    )

            time.sleep(0.1)

        logging.info(
            f"Validation complete: {len(validated_resolvers)} resolvers passed"
        )

        if not validated_resolvers:
            logging.warning("No resolvers passed validation")
            # Write empty CSV with headers
            fieldnames = ["ip", "rtt_ms"]
            if not skip_reverse_dns:
                fieldnames.append("reverse_dns")
            if not skip_chaos:
                fieldnames.extend(["chaos_hostname", "chaos_version", "chaos_id"])
            if not skip_enrich:
                fieldnames.extend(["ASN", "AS_Name"])

            with open(output, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

            logging.info(f"Empty results written to {output}")
            return 0

        if not skip_reverse_dns or not skip_chaos:
            logging.info("Querying DNS metadata...")

            def query_dns_metadata(resolver_data):
                ip = resolver_data["ip"]

                if not skip_reverse_dns:
                    resolver_data["reverse_dns"] = get_reverse_dns(ip) or ""

                if not skip_chaos:
                    resolver_data["chaos_hostname"] = (
                        query_chaos_txt(ip, "hostname.bind") or ""
                    )
                    resolver_data["chaos_version"] = (
                        query_chaos_txt(ip, "version.bind") or ""
                    )
                    resolver_data["chaos_id"] = query_chaos_txt(ip, "id.server") or ""

                return resolver_data

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = [
                    executor.submit(query_dns_metadata, resolver)
                    for resolver in validated_resolvers
                ]

                for future in tqdm(
                    concurrent.futures.as_completed(futures),
                    total=len(futures),
                    desc="Querying DNS metadata",
                ):
                    try:
                        future.result()
                    except Exception as e:
                        logging.error(f"Error querying DNS metadata: {e}")

        if not skip_enrich:
            logging.info("Enriching with ASN data...")

            for resolver in tqdm(validated_resolvers, desc="Enriching resolvers"):
                ip = resolver["ip"]
                asn = ip2asn(ip, asndb)
                asname = asn2name(asn, asnames)

                # Fallback to ipinfo.io if pyasn couldn't resolve (private/gateway IPs)
                if asn is None:
                    logging.info(f"pyasn miss for {ip}, falling back to ipinfo.io...")
                    asn, asname = ipinfo_lookup(ip)

                resolver["ASN"] = asn or ""
                resolver["AS_Name"] = asname or ""

        logging.info("Writing results...")

        # Determine fieldnames based on what data was collected
        fieldnames = ["ip", "rtt_ms"]
        if not skip_reverse_dns:
            fieldnames.append("reverse_dns")
        if not skip_chaos:
            fieldnames.extend(["chaos_hostname", "chaos_version", "chaos_id"])
        if not skip_enrich:
            fieldnames.extend(["ASN", "AS_Name"])

        with open(output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(validated_resolvers)

        logging.info(f"Results written to {output}")
        logging.info(f"Total validated resolvers: {len(validated_resolvers)}")
        return 0

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1


def register_parser(subparsers):
    """Register the validate subcommand"""
    parser = subparsers.add_parser(
        "validate",
        help="Validate DNS resolvers and enrich with metadata",
        description="""
Validate DNS resolvers against a test domain and enrich with ASN data and DNS metadata.

ASN databases are automatically downloaded on first run. The validation process:
1. Tests resolvers against a baseline domain (e.g., example.com)
2. Enriches with reverse DNS lookups
3. Queries CHAOS TXT records (hostname.bind, version.bind, id.server)
4. Adds ASN and AS name information

Output CSV includes: ip, rtt_ms, reverse_dns, chaos_*, ASN, AS_Name
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required arguments
    parser.add_argument(
        "resolvers", help="File containing DNS server IPs (one per line)"
    )

    parser.add_argument("domain", help="Domain to test against (e.g., example.com)")

    # Output options
    parser.add_argument(
        "-o",
        "--output",
        help="Output CSV file (default: validated_resolvers_<timestamp>.csv)",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Batch size for processing (default: 100)",
    )

    # Skip flags
    parser.add_argument(
        "--skip-enrich",
        action="store_true",
        help="Skip ASN enrichment (no ASN or AS_Name columns in output)",
    )

    parser.add_argument(
        "--skip-reverse-dns",
        action="store_true",
        help="Skip reverse DNS lookups (no reverse_dns column in output)",
    )

    parser.add_argument(
        "--skip-chaos",
        action="store_true",
        help="Skip CHAOS TXT queries (no chaos_* columns in output)",
    )

    # Database paths (for enrichment)
    parser.add_argument(
        "--ipasn-db",
        help="Path to IP-ASN database (default: auto-detect from data/ipasn.db)",
    )

    parser.add_argument(
        "--asnames",
        help="Path to AS names JSON file (default: auto-detect from data/asnames.json)",
    )

    # Setup parameters (used when auto-running setup)
    parser.add_argument(
        "--setup-output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for database files (default: {DEFAULT_OUTPUT_DIR})",
    )

    parser.add_argument(
        "--setup-year",
        type=int,
        help="Year for BGP data download (default: current year)",
    )

    parser.add_argument(
        "--setup-month",
        type=int,
        help="Month for BGP data download (default: current month)",
    )

    parser.set_defaults(
        func=lambda args: validate_resolvers(
            args.resolvers,
            args.domain,
            args.output,
            args.batch_size,
            args.skip_enrich,
            args.skip_reverse_dns,
            args.skip_chaos,
            args.ipasn_db,
            args.asnames,
            args.setup_output_dir,
            args.setup_year,
            args.setup_month,
        )
    )
