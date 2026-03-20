#!/usr/bin/env python3
"""
blockbust CLI - command-line wrapper around ZDNS with censorship detection utilities
"""

import argparse
import logging
import sys
from pathlib import Path


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog="blockbust",
        description="Command-line wrapper around ZDNS with censorship detection utilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Workflow:
  1. Validate and enrich DNS resolvers (auto-downloads ASN databases)
     blockbust validate resolvers.txt example.com -o validated.csv

  2. Build censorship detection rules from known-blocked domain
     blockbust build-rules -i validated.csv -d thepiratebay.org

  3. Detect censorship at scale
     blockbust detect --input domains.txt --rule rules/network-asn.yaml --verify 8.8.8.8

Requirements:
  - ZDNS binary must be installed (see: https://github.com/zmap/ZDNS#install)
  - Resolver IPs must be obtained externally (Censys, Shodan, masscan, etc.)

        """,
    )

    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    subparsers = parser.add_subparsers(
        title="commands",
        description="Available commands",
        dest="command",
        help="Command to run",
    )

    # Import command modules
    from blockbust.commands import validate, build, detect

    # Register subcommands
    validate.register_parser(subparsers)
    build.register_parser(subparsers)
    detect.register_parser(subparsers)

    # Parse arguments
    args = parser.parse_args()

    # If no command specified, show help
    if not args.command:
        parser.print_help()
        return 1

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Execute command
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
