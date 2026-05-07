#!/usr/bin/env python3
"""
Export plugin-text-search results for multiple keywords to a single CSV file.

For each keyword the script calls POST /api/v1/vulnerabilities/plugin-text-search
and pages through the complete result set. All results across all keywords are
written to one output CSV. A 'keyword' column is added to every row so you can
tell which search produced each record.

Duplicate records (same row found by two different keywords) are kept — filter
or deduplicate in Excel / pandas as needed.

Usage
-----
  python plugin_text_search_export.py [OPTIONS]

Options
-------
  --base-url       Base URL of the Spring Boot API    (default: http://localhost:8080)
  --region         Tenable SC region name              (default: APAC)
  --keyword        Single keyword (optional if --keywords-file is given)
  --keywords-file  Path to a file with one keyword per line; blank lines and
                   lines starting with '#' are ignored (optional if --keyword given)
  --columns        Comma-separated columns to return   (optional; omit for all fields)
  --filters        JSON array of extra SC filters ANDed with each pluginText search
  --page-size      Records per page                    (default: 1000)
  --output         Output CSV file path                (default: result.csv)

At least one of --keyword or --keywords-file must be provided.

Keywords file format
--------------------
  One keyword per line.  Blank lines and lines starting with '#' are ignored.

  Example keywords.txt:
    # CVEs
    CVE-2021-44228
    CVE-2022-22965

    # product names
    log4j
    spring4shell

Environment variables (override defaults, overridden by CLI flags)
------------------------------------------------------------------
  TENABLE_BASE_URL, TENABLE_REGION, TENABLE_KEYWORD, TENABLE_KEYWORDS_FILE,
  TENABLE_COLUMNS, TENABLE_FILTERS, TENABLE_PAGE_SIZE, TENABLE_OUTPUT

Examples
--------
  # Single keyword
  python plugin_text_search_export.py --region APAC --keyword "log4j"

  # Multiple keywords from a file
  python plugin_text_search_export.py --region APAC --keywords-file keywords.txt

  # Combined, with severity filter and column selection
  python plugin_text_search_export.py \\
    --region APAC \\
    --keyword "heartbleed" \\
    --keywords-file keywords.txt \\
    --columns "pluginID,ip,pluginName,severity,pluginText" \\
    --filters '[{"filterName":"severity","operator":"=","value":"4"}]' \\
    --output result.csv
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
        description=(
            "Export Tenable SC plugin-text-search results for multiple keywords "
            "into a single CSV file."
        )
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
        "--keyword",
        default=os.getenv("TENABLE_KEYWORD", ""),
        help="Single keyword to search for (optional if --keywords-file is given)",
    )
    p.add_argument(
        "--keywords-file",
        default=os.getenv("TENABLE_KEYWORDS_FILE", ""),
        metavar="FILE",
        help=(
            "Path to a file with one keyword per line. "
            "Blank lines and lines starting with '#' are ignored."
        ),
    )
    p.add_argument(
        "--columns",
        default=os.getenv("TENABLE_COLUMNS", ""),
        help="Comma-separated columns to include in each response record (optional)",
    )
    p.add_argument(
        "--filters",
        default=os.getenv("TENABLE_FILTERS", ""),
        help=(
            "JSON array of extra Tenable SC filters ANDed with each pluginText search. "
            'Example: \'[{"filterName":"severity","operator":"=","value":"4"}]\''
        ),
    )
    p.add_argument(
        "--page-size",
        type=int,
        default=int(os.getenv("TENABLE_PAGE_SIZE", "1000")),
        help="Records per page for each keyword search (default: 1000)",
    )
    p.add_argument(
        "--output",
        default=os.getenv("TENABLE_OUTPUT", "result.csv"),
        help="Output CSV file path (default: result.csv)",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Keyword loading
# ---------------------------------------------------------------------------

def load_keywords(keyword_arg: str, keywords_file_arg: str) -> list[str]:
    """Merge keywords from --keyword and --keywords-file, deduplicated, order preserved."""
    keywords: list[str] = []

    if keyword_arg.strip():
        keywords.append(keyword_arg.strip())

    if keywords_file_arg.strip():
        path = keywords_file_arg.strip()
        if not os.path.isfile(path):
            print(f"ERROR: --keywords-file '{path}' not found.", file=sys.stderr)
            sys.exit(1)
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    word = line.strip()
                    if word and not word.startswith("#"):
                        keywords.append(word)
        except OSError as exc:
            print(f"ERROR: Cannot read --keywords-file: {exc}", file=sys.stderr)
            sys.exit(1)

    # Deduplicate while preserving insertion order
    seen: dict[str, None] = {}
    for kw in keywords:
        seen[kw] = None

    return list(seen)


# ---------------------------------------------------------------------------
# API call
# ---------------------------------------------------------------------------

def fetch_page(
    session: requests.Session,
    base_url: str,
    region: str,
    keyword: str,
    columns: list[str],
    filters: list[dict],
    start_offset: int,
    page_size: int,
) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/api/v1/vulnerabilities/plugin-text-search"
    params = {
        "region": region,
        "startOffset": start_offset,
        "endOffset": start_offset + page_size,
    }
    body: dict[str, Any] = {"keyword": keyword}
    if columns:
        body["columns"] = columns
    if filters:
        body["filters"] = filters

    response = session.post(url, params=params, json=body, timeout=120)
    response.raise_for_status()
    return response.json()


def fetch_all_for_keyword(
    session: requests.Session,
    base_url: str,
    region: str,
    keyword: str,
    columns: list[str],
    filters: list[dict],
    page_size: int,
) -> list[dict[str, Any]]:
    """
    Pages through the full result set for a single keyword and returns all rows.
    Each row has 'keyword' prepended so results can be distinguished in the CSV.
    """
    rows: list[dict[str, Any]] = []
    start_offset = 0
    total_records: int | None = None
    page_number = 0

    while True:
        page_number += 1
        total_pages = math.ceil(total_records / page_size) if total_records else "?"
        end_offset = min(start_offset + page_size, total_records) if total_records else start_offset + page_size
        print(
            f"    Page {page_number}/{total_pages} | "
            f"records {start_offset + 1}–{end_offset} of {total_records or '?'} | fetching ...",
            end=" ",
            flush=True,
        )

        try:
            data = fetch_page(
                session=session,
                base_url=base_url,
                region=region,
                keyword=keyword,
                columns=columns,
                filters=filters,
                start_offset=start_offset,
                page_size=page_size,
            )
        except requests.HTTPError as exc:
            print(
                f"\n  ERROR: HTTP {exc.response.status_code} — {exc.response.text}",
                file=sys.stderr,
            )
            sys.exit(1)
        except requests.RequestException as exc:
            print(f"\n  ERROR: Request failed — {exc}", file=sys.stderr)
            sys.exit(1)

        if total_records is None:
            total_records = data.get("totalRecords", 0)
            total_pages = math.ceil(total_records / page_size) if total_records else 1
            end_offset = min(start_offset + page_size, total_records)

        page_results: list[dict] = data.get("results") or []
        returned = data.get("returnedRecords", len(page_results))

        for record in page_results:
            row = {"keyword": keyword}
            row.update(flatten_values(record))
            rows.append(row)

        processed = min(start_offset + page_size, total_records)
        pct = int(processed / total_records * 100) if total_records else 0
        print(
            f"done | records this page: {returned} | "
            f"collected: {len(rows)} | "
            f"progress: {processed}/{total_records} ({pct}%)"
        )

        start_offset += page_size
        if total_records is not None and start_offset >= total_records:
            print(f"    Completed '{keyword}': {total_records} records processed, {len(rows)} collected.")
            break

        time.sleep(0.1)

    return rows


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

def flatten_values(row: dict[str, Any]) -> dict[str, Any]:
    """Flatten nested dicts/lists so values write cleanly to CSV."""
    flat: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, dict):
            flat[key] = json.dumps(value, ensure_ascii=False)
        elif isinstance(value, list):
            flat[key] = " | ".join(str(v) for v in value)
        else:
            flat[key] = value
    return flat


def build_fieldnames(all_rows: list[dict[str, Any]], columns: list[str]) -> list[str]:
    """
    Return an ordered list of CSV column names.
    'keyword' is always first. When --columns was specified those come next in
    the requested order, followed by any extra fields seen in the data.
    """
    seen: dict[str, None] = {}
    for row in all_rows:
        for key in row:
            seen[key] = None
    all_keys = list(seen)

    if columns:
        ordered = ["keyword"] + [c for c in columns if c != "keyword"]
        extra = [k for k in all_keys if k not in ordered]
        return ordered + extra
    else:
        # keyword first, then everything else in encounter order
        rest = [k for k in all_keys if k != "keyword"]
        return ["keyword"] + rest


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    keywords = load_keywords(args.keyword, args.keywords_file)
    if not keywords:
        print(
            "ERROR: No keywords supplied. Use --keyword and/or --keywords-file.",
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

    print("Plugin-text-search export (server-side filter, multi-keyword)")
    print(f"  Base URL      : {args.base_url}")
    print(f"  Region        : {args.region}")
    print(f"  Keywords ({len(keywords):>3}) : {keywords}")
    print(f"  Columns       : {columns or '(all)'}")
    print(f"  Filters       : {filters or '(none)'}")
    print(f"  Page size     : {args.page_size}")
    print(f"  Output        : {args.output}")
    print()

    all_rows: list[dict[str, Any]] = []

    for idx, keyword in enumerate(keywords, start=1):
        print(f"[{idx}/{len(keywords)}] Searching for: '{keyword}'")
        rows = fetch_all_for_keyword(
            session=session,
            base_url=args.base_url,
            region=args.region,
            keyword=keyword,
            columns=columns,
            filters=filters,
            page_size=args.page_size,
        )
        print(f"  -> {len(rows)} record(s) collected for '{keyword}'\n")
        all_rows.extend(rows)

    print(f"Total records across all keywords: {len(all_rows)}")

    if not all_rows:
        print("No matching records found. CSV will not be written.")
        sys.exit(0)

    fieldnames = build_fieldnames(all_rows, columns)

    with open(args.output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames,
            extrasaction="ignore",
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"Exported {len(all_rows)} record(s) to: {args.output}")


if __name__ == "__main__":
    main()
