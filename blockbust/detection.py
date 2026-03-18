"""
DNS censorship detection logic
"""

import argparse
import yaml
import json
import subprocess
import shutil
from pathlib import Path
import logging
from datetime import datetime
from typing import Dict, Optional, Set
from tqdm import tqdm
from dataclasses import dataclass


@dataclass
class QueryStats:
    total: int = 0
    matched: int = 0
    failed: int = 0
    servfail: int = 0
    timeout: int = 0


class RuleProcessor:
    def __init__(
        self,
        rules_file: Path,
        pattern_name: str = "primary",
        verify_resolver: Optional[str] = None,
    ):
        self.pattern_name = pattern_name
        self.verify_resolver = verify_resolver
        self._check_zdns_installed()
        self.rules = self._load_rules(rules_file)
        self.network_info = self.rules["network_info"]
        self.signature = self._get_signature()
        self.logger = logging.getLogger(__name__)

    def _check_zdns_installed(self):
        """Check if zdns binary is available"""
        if not shutil.which("zdns"):
            raise FileNotFoundError(
                "zdns binary not found. Please install zdns first:\n"
                "Installation instructions: https://github.com/zmap/zdns?tab=readme-ov-file#install"
            )

    def _extract_resolver_ips(self, resolvers: list) -> list:
        return [r["ip"] for r in resolvers]

    def _load_rules(self, rules_file: Path) -> dict:
        with open(rules_file) as f:
            return yaml.safe_load(f)

    def is_domain_not_found_pattern(self) -> bool:
        return self.signature.get("pattern") == "domain_not_found"

    def _get_signature(self) -> dict:
        """Get signature block for specified pattern name"""
        signatures = self.network_info["signatures"]

        for sig in signatures:
            if sig.get("name") == self.pattern_name:
                if (
                    sig.get("pattern") == "domain_not_found"
                    and not self.verify_resolver
                ):
                    raise ValueError(
                        "--verify resolver required for domain_not_found pattern"
                    )
                if sig.get("pattern") == "no_answer" and not self.verify_resolver:
                    raise ValueError("--verify resolver required for no_answer pattern")
                return sig

        if self.pattern_name == "primary":
            raise ValueError("No primary pattern found in rules")
        else:
            raise ValueError(f"Pattern '{self.pattern_name}' not found in rules")

    def run_zdns_query(self, domains_file: Path, output_file: Path, threads: int):
        domain_count = sum(1 for _ in open(domains_file))
        resolver_list = ",".join(
            self._extract_resolver_ips(self.signature["resolvers"])
        )

        cmd = [
            "zdns",
            "A",
            "--name-servers",
            resolver_list,
            "--input-file",
            str(domains_file),
            "--threads",
            str(threads),
            "--retries",
            "3",
        ]

        self.logger.info(
            f"Testing pattern '{self.pattern_name}' ({self.signature['pattern']})"
        )
        self.logger.info(f"Using resolvers: {resolver_list}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        with open(output_file, "w") as outfile:
            processed = 0
            with tqdm(total=domain_count, desc="Querying domains") as pbar:
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                    if line:
                        outfile.write(line)
                        outfile.flush()
                        processed += 1
                        pbar.update(1)

        if process.returncode != 0:
            stderr = process.stderr.read()
            raise Exception(f"zdns query failed: {stderr}")

        self.logger.info(f"Query complete. Results saved to {output_file}")

    def verify_matches(
        self, domains: Set[str], resolver: str, check_nxdomain: bool = False
    ) -> Set[str]:
        """Verify matched domains using a trusted resolver"""
        temp_domains = Path("data/temp_verify_domains.txt")
        temp_results = Path("data/temp_verify_results.jsonl")

        with open(temp_domains, "w") as f:
            for domain in domains:
                f.write(f"{domain}\n")

        cmd = [
            "zdns",
            "A",
            "--name-servers",
            resolver,
            "--input-file",
            str(temp_domains),
            "--threads",
            "50",
            "--retries",
            "3",
        ]

        process = subprocess.run(
            cmd, stdout=open(temp_results, "w"), stderr=subprocess.PIPE, text=True
        )

        if process.returncode != 0:
            raise Exception(f"Verification query failed: {process.stderr}")

        censored_domains = set()
        with open(temp_results) as f:
            for line in f:
                if not line.strip():
                    continue
                result = json.loads(line)

                if check_nxdomain:
                    status = result.get("results", {}).get("A", {}).get("status", "")
                    if status == "NXDOMAIN":
                        censored_domains.add(result["name"])
                else:
                    if self.signature["type"] == "NODATA":
                        answers = (
                            result.get("results", {})
                            .get("A", {})
                            .get("data", {})
                            .get("answers", [])
                        )
                        if answers:
                            censored_domains.add(result["name"])
                    else:
                        if not self.check_censorship(result):
                            censored_domains.add(result["name"])

        temp_domains.unlink()
        temp_results.unlink()

        return censored_domains

    def process_results(
        self, results_file: Path, matched_output: Path, failed_output: Path
    ) -> QueryStats:
        stats = QueryStats()
        matched_domains = set()
        nxdomain_domains = set()

        with open(matched_output, "w") as matched_file, open(
            failed_output, "w"
        ) as failed_file:
            with open(results_file) as f:
                for line in f:
                    if not line.strip():
                        continue

                    stats.total += 1
                    result = json.loads(line)

                    a_results = result.get("results", {}).get("A", {})
                    status = a_results.get("status", "")
                    error = a_results.get("error", "")

                    if status == "NXDOMAIN":
                        if self.is_domain_not_found_pattern():
                            nxdomain_domains.add(result["name"])
                            continue
                        else:
                            stats.failed += 1
                            failed_file.write(f"{result['name']},NXDOMAIN\n")
                            continue

                    if status == "SERVFAIL":
                        stats.failed += 1
                        stats.servfail += 1
                        failed_file.write(f"{result['name']},SERVFAIL\n")
                        continue

                    if status == "TIMEOUT":
                        stats.failed += 1
                        stats.timeout += 1
                        failed_file.write(f"{result['name']},TIMEOUT\n")
                        continue

                    if "lookup failed" in error:
                        stats.failed += 1
                        failed_file.write(f"{result['name']},{error}\n")
                        continue

                    censorship = self.check_censorship(result)
                    if censorship:
                        matched_domains.add(result["name"])

        final_matches = matched_domains
        if self.verify_resolver:
            if self.is_domain_not_found_pattern():
                tqdm.write(
                    f"Verifying {len(nxdomain_domains)} NXDOMAIN responses..."
                )
                verified_nxdomains = self.verify_matches(
                    nxdomain_domains, self.verify_resolver, check_nxdomain=True
                )
                final_matches = nxdomain_domains - verified_nxdomains
                tqdm.write(
                    f"Found {len(final_matches)} censored domains (NXDOMAIN mismatches)"
                )
            elif matched_domains:
                tqdm.write(f"Verifying {len(matched_domains)} matched domains...")
                verified_matches = self.verify_matches(
                    matched_domains, self.verify_resolver, check_nxdomain=False
                )
                final_matches = verified_matches
                tqdm.write(
                    f"Found {len(final_matches)} confirmed censored domains"
                )

        with open(matched_output, "w") as f:
            for domain in final_matches:
                f.write(f"{domain}\n")

        stats.matched = len(final_matches)
        return stats

    def check_censorship(self, result: Dict) -> Optional[Dict]:
        dns_data = result.get("results", {}).get("A", {})
        status = dns_data.get("status", "")
        answers = dns_data.get("data", {}).get("answers", [])

        if self.signature["type"] == "NODATA" and status == "NOERROR" and not answers:
            return {
                "domain": result["name"],
                "signature_matched": self.signature,
                "response": "empty_response",
            }

        for answer in answers:
            if (
                answer["type"] == self.signature["type"]
                and answer["answer"] == self.signature["pattern"]
            ):
                return {
                    "domain": result["name"],
                    "signature_matched": self.signature,
                    "response": answers,
                }
        return None
