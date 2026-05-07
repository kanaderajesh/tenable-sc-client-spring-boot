#!/usr/bin/env python3
"""
Export all keyword-search results from Tenable SC Spring Boot API to a CSV file.

Usage
-----
  python keyword_search_export.py [OPTIONS]

Options
-------
  --base-url       Base URL of the Spring Boot API   (default: http://localhost:8080)
  --region         Tenable SC region name             (default: APAC)
  --keywords       Comma-separated list of keywords   (optional if --keywords-file given)
  --keywords-file  Path to a file with one keyword per line; blank lines and lines
                   starting with '#' are ignored      (optional if --keywords given)
  --columns        Comma-separated list of columns    (optional; omit for all fields)
  --filters        JSON array string of filter objects (optional)
  --page-size      Records per page                   (default: 1000)
  --output         Output CSV file path               (default: keyword_search_results.csv)

At least one of --keywords or --keywords-file must be provided. Both may be used
together — the keyword lists are merged and deduplicated while preserving order.

Keywords file format
--------------------
  One keyword per line. Blank lines and lines starting with '#' are ignored.

  Example keywords.txt:
    # CVE identifiers
    CVE-2021-44228
    CVE-2022-22965

    # product names
    log4j
    spring4shell

Environment variables (override defaults, overridden by CLI flags)
------------------------------------------------------------------
  TENABLE_BASE_URL, TENABLE_REGION, TENABLE_KEYWORDS, TENABLE_KEYWORDS_FILE,
  TENABLE_COLUMNS, TENABLE_FILTERS, TENABLE_PAGE_SIZE, TENABLE_OUTPUT

Examples
--------
  # Keywords inline
  python keyword_search_export.py \\
    --base-url http://localhost:8080 \\
    --region APAC \\
    --keywords "CVE-2021-44228,log4j,remote code execution" \\
    --columns "pluginID,ip,pluginName,severity,pluginText" \\
    --filters '[{"filterName":"severity","operator":"=","value":"4"}]' \\
    --output results.csv

  # Keywords from file
  python keyword_search_export.py \\
    --region APAC \\
    --keywords-file keywords.txt \\
    --output results.csv

  # Both (merged)
  python keyword_search_export.py \\
    --region APAC \\
    --keywords "extra-keyword" \\
    --keywords-file keywords.txt \\
    --output results.csv
"""

import argparse
import csv
import json
import math
import os
import sys
import time
from typing import Any

import requests


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Export Tenable SC keyword-search results to CSV."
    )
    p.add_argument(
        "--base-url",
        default=os.getenv("TENABLE_BASE_URL", "http://localhost:8080"),
        help="Spring Boot API base URL (default: http://localhost:8080)",
    )
    p.add_argument(
        "--region",
        default=os.getenv("TENABLE_REGION", "APAC"),
        help="Tenable SC region name (default: APAC)",
    )
    p.add_argument(
        "--keywords",
        default=os.getenv("TENABLE_KEYWORDS", ""),
        help="Comma-separated keywords to search for in plugin output text",
    )
    p.add_argument(
        "--keywords-file",
        default=os.getenv("TENABLE_KEYWORDS_FILE", ""),
        metavar="FILE",
        help="Path to a file with one keyword per line (blank lines and '#' comments ignored)",
    )
    p.add_argument(
        "--columns",
        default=os.getenv("TENABLE_COLUMNS", ""),
        help="Comma-separated columns to include in the response (optional)",
    )
    p.add_argument(
        "--filters",
        default=os.getenv("TENABLE_FILTERS", ""),
        help="JSON array of Tenable SC filters, e.g. "
             '[{"filterName":"severity","operator":"=","value":"4"}]',
    )
    p.add_argument(
        "--page-size",
        type=int,
        default=int(os.getenv("TENABLE_PAGE_SIZE", "1000")),
        help="Number of records per page (default: 1000)",
    )
    p.add_argument(
        "--output",
        default=os.getenv("TENABLE_OUTPUT", "keyword_search_results.csv"),
        help="Output CSV file path (default: keyword_search_results.csv)",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# API call
# ---------------------------------------------------------------------------

def fetch_page(
    session: requests.Session,
    base_url: str,
    region: str,
    keywords: list[str],
    columns: list[str],
    filters: list[dict],
    start_offset: int,
    page_size: int,
) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/api/v1/vulnerabilities/keyword-search"
    params = {
        "region": region,
        "startOffset": start_offset,
        "endOffset": start_offset + page_size,
    }
    body: dict[str, Any] = {"keywords": keywords}
    if columns:
        body["columns"] = columns
    if filters:
        body["filters"] = filters

    response = session.post(url, params=params, json=body, timeout=120)
    response.raise_for_status()
    return response.json()


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

def flatten_record(result: dict[str, Any]) -> dict[str, Any]:
    """
    Merge 'fields' into a flat dict and append 'matchedKeywords' as a
    pipe-separated string.
    """
    row: dict[str, Any] = {}
    for key, value in (result.get("fields") or {}).items():
        row[key] = value
    matched = result.get("matchedKeywords") or []
    row["matchedKeywords"] = " | ".join(matched)
    return row


def collect_fieldnames(all_rows: list[dict[str, Any]]) -> list[str]:
    """Return a stable, ordered list of all column names seen across all rows."""
    seen: dict[str, None] = {}
    for row in all_rows:
        for key in row:
            seen[key] = None
    return list(seen)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # Collect keywords from --keywords (comma-separated)
    raw_keywords: list[str] = [k.strip() for k in args.keywords.split(",") if k.strip()]

    # Collect keywords from --keywords-file (one per line, # comments, blank lines ignored)
    keywords_file = args.keywords_file.strip()
    if keywords_file:
        if not os.path.isfile(keywords_file):
            print(f"ERROR: --keywords-file '{keywords_file}' not found.", file=sys.stderr)
            sys.exit(1)
        try:
            with open(keywords_file, encoding="utf-8") as fh:
                for line in fh:
                    word = line.strip()
                    if word and not word.startswith("#"):
                        raw_keywords.append(word)
        except OSError as exc:
            print(f"ERROR: Cannot read --keywords-file: {exc}", file=sys.stderr)
            sys.exit(1)

    # Deduplicate while preserving insertion order
    seen: dict[str, None] = {}
    for kw in raw_keywords:
        seen[kw] = None
    raw_keywords = list(seen)

    if not raw_keywords:
        print(
            "ERROR: No keywords supplied. Use --keywords and/or --keywords-file.",
            file=sys.stderr,
        )
        sys.exit(1)

    columns = [c.strip() for c in args.columns.split(",") if c.strip()]

    filters: list[dict] = []
    if args.filters.strip():
        try:
            filters = json.loads(args.filters)
            if not isinstance(filters, list):
                raise ValueError("filters must be a JSON array")
        except (json.JSONDecodeError, ValueError) as exc:
            print(f"ERROR: --filters is not valid JSON: {exc}", file=sys.stderr)
            sys.exit(1)

    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})

    all_rows: list[dict[str, Any]] = []
    start_offset = 0
    total_records: int | None = None
    page_number = 0

    keyword_source = []
    if args.keywords.strip():
        keyword_source.append("--keywords")
    if keywords_file:
        keyword_source.append(f"--keywords-file ({keywords_file})")

    print("Starting keyword search export")
    print(f"  Base URL        : {args.base_url}")
    print(f"  Region          : {args.region}")
    print(f"  Keyword source  : {', '.join(keyword_source)}")
    print(f"  Total keywords  : {len(raw_keywords)}")
    print(f"  Keywords        : {raw_keywords}")
    print(f"  Columns         : {columns or '(all)'}")
    print(f"  Filters         : {filters or '(none)'}")
    print(f"  Page size       : {args.page_size}")
    print()

    while True:
        page_number += 1
        end_offset = min(start_offset + args.page_size, total_records) if total_records else start_offset + args.page_size
        total_pages = math.ceil(total_records / args.page_size) if total_records else "?"
        print(
            f"  Page {page_number}/{total_pages} | "
            f"records {start_offset + 1}–{end_offset} of {total_records or '?'} | fetching ...",
            end=" ",
            flush=True,
        )

        try:
            data = fetch_page(
                session=session,
                base_url=args.base_url,
                region=args.region,
                keywords=raw_keywords,
                columns=columns,
                filters=filters,
                start_offset=start_offset,
                page_size=args.page_size,
            )
        except requests.HTTPError as exc:
            print(f"\nERROR: HTTP {exc.response.status_code} — {exc.response.text}", file=sys.stderr)
            sys.exit(1)
        except requests.RequestException as exc:
            print(f"\nERROR: Request failed — {exc}", file=sys.stderr)
            sys.exit(1)

        if total_records is None:
            total_records = data.get("totalRecords", 0)
            total_pages = math.ceil(total_records / args.page_size) if total_records else 1
            end_offset = min(start_offset + args.page_size, total_records)

        page_results: list[dict] = data.get("results") or []
        returned = data.get("returnedRecords", len(page_results))
        matched_this_page = len(page_results)

        for result in page_results:
            all_rows.append(flatten_record(result))

        pct = int(min(start_offset + args.page_size, total_records) / total_records * 100) if total_records else 0
        print(
            f"done | SC records this page: {returned} | "
            f"matched this page: {matched_this_page} | "
            f"total matched: {len(all_rows)} | "
            f"progress: {min(start_offset + args.page_size, total_records)}/{total_records} ({pct}%)"
        )

        # Advance offset
        start_offset += args.page_size

        # Stop when we have consumed all SC records
        if total_records is not None and start_offset >= total_records:
            print(
                f"\n  Completed: {total_records} SC records processed across "
                f"{page_number} page(s), {len(all_rows)} total keyword matches."
            )
            break

        # Brief pause to be a polite API client
        time.sleep(0.1)

    if not all_rows:
        print("\nNo matching records found. CSV will not be written.")
        sys.exit(0)

    # Determine CSV columns: use requested columns order when specified
    if columns:
        fieldnames = [c for c in columns if c != "matchedKeywords"]
        fieldnames.append("matchedKeywords")
        # Add any extra fields that came back but weren't in the requested list
        extra = [f for f in collect_fieldnames(all_rows) if f not in fieldnames]
        fieldnames.extend(extra)
    else:
        fieldnames = collect_fieldnames(all_rows)
        # Ensure matchedKeywords is last
        if "matchedKeywords" in fieldnames:
            fieldnames.remove("matchedKeywords")
        fieldnames.append("matchedKeywords")

    output_path = args.output
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames,
            extrasaction="ignore",
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\nExported {len(all_rows)} record(s) to: {output_path}")


if __name__ == "__main__":
    main()
