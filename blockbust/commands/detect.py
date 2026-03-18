"""
Detect DNS censorship using rules
"""

import logging
from pathlib import Path
from datetime import datetime
from blockbust.detection import RuleProcessor

logger = logging.getLogger(__name__)


def detect_censorship(input_file, rule_file, pattern='primary', cached=False,
                     threads=1000, verify=None, output_dir='data/results'):
    """Run censorship detection using ZDNS and rules"""

    rule_path = Path(rule_file)
    input_path = Path(input_file)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if not rule_path.exists():
        logger.error(f"Rule file not found: {rule_path}")
        return 1

    try:
        detector = RuleProcessor(rule_path, pattern, verify_resolver=verify)

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        rule_name = rule_path.stem
        results_path = output_path / f"{rule_name}_ZDNS_results_{timestamp}.jsonl"
        matched_path = output_path / f"{rule_name}_matched_domains_{timestamp}.txt"
        failed_path = output_path / f"{rule_name}_failed_queries_{timestamp}.txt"

        if not cached:
            detector.logger.info(f"Starting fresh query run with {threads} threads")
            detector.run_zdns_query(input_path, results_path, threads)
        else:
            detector.logger.info("Using cached results")
            cached_results = sorted(output_path.glob(f'{rule_name}_ZDNS_results_*.jsonl'))
            if not cached_results:
                logger.error(f"No cached results found for {rule_name}")
                return 1
            results_path = cached_results[-1]
            detector.logger.info(f"Using most recent results file: {results_path}")

        stats = detector.process_results(results_path, matched_path, failed_path)

        logger.info(f"Total domains checked: {stats.total}")
        logger.info(f"Matched domains: {stats.matched}")
        logger.info(f"Failed queries: {stats.failed}")
        logger.info(f"Matched domains written to: {matched_path}")
        logger.info(f"Failed queries written to: {failed_path}")

        return 0

    except ValueError as e:
        logger.error(str(e))
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1

def register_parser(subparsers):
    """Register the detect subcommand"""
    parser = subparsers.add_parser(
        'detect',
        help='Detect DNS censorship using rules',
        description='Use ZDNS and rule files to detect censored domains at scale'
    )

    parser.add_argument(
        '--input',
        required=True,
        help='Input file containing domains to test'
    )

    parser.add_argument(
        '--rule',
        required=True,
        help='Path to YAML rule file (or just the rule name from rules/ directory)'
    )

    parser.add_argument(
        '--pattern',
        default='primary',
        help='Pattern name to test (default: primary). Use alt1, alt2, etc. for alternative signatures'
    )

    parser.add_argument(
        '--cached',
        action='store_true',
        help='Use cached ZDNS results instead of re-querying'
    )

    parser.add_argument(
        '--threads',
        type=int,
        default=1000,
        help='Number of ZDNS threads (default: 1000)'
    )

    parser.add_argument(
        '--verify',
        metavar='RESOLVER',
        help='Verify matches using specified resolver (e.g., 8.8.8.8). Required for 127.0.0.1 patterns and NXDOMAIN blocking'
    )

    parser.add_argument(
        '--output-dir',
        default='data/results',
        help='Output directory for results (default: data/results)'
    )

    parser.set_defaults(func=lambda args: detect_censorship(
        args.input,
        args.rule,
        args.pattern,
        args.cached,
        args.threads,
        args.verify,
        args.output_dir
    ))
