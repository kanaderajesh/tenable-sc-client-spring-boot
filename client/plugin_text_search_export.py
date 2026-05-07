#!/usr/bin/env python3
"""
Export all plugin-text-search results from Tenable SC Spring Boot API to a CSV file.

This script uses the POST /api/v1/vulnerabilities/plugin-text-search endpoint, which
delegates keyword matching to Tenable SC as a native pluginText filter (server-side).
Only records that satisfy the filter are returned — no client-side scanning is performed.

Use this script for targeted single-keyword searches. For scanning 300+ keywords
simultaneously use keyword_search_export.py instead.

Usage
-----
  python plugin_text_search_export.py [OPTIONS]

Options
-------
  --base-url   Base URL of the Spring Boot API    (default: http://localhost:8080)
  --region     Tenable SC region name              (default: APAC)
  --keyword    Keyword to search for in pluginText (required)
  --columns    Comma-separated list of columns     (optional; omit for all fields)
  --filters    JSON array string of filter objects (optional; ANDed with pluginText filter)
  --page-size  Records per page                    (default: 1000)
  --output     Output CSV file path                (default: plugin_text_search_results.csv)

Environment variables (override defaults, overridden by CLI flags)
------------------------------------------------------------------
  TENABLE_BASE_URL, TENABLE_REGION, TENABLE_KEYWORD,
  TENABLE_COLUMNS, TENABLE_FILTERS, TENABLE_PAGE_SIZE, TENABLE_OUTPUT

Examples
--------
  # Basic
  python plugin_text_search_export.py --region APAC --keyword "log4j"

  # With severity filter and column selection
  python plugin_text_search_export.py \\
    --base-url http://localhost:8080 \\
    --region APAC \\
    --keyword "log4j" \\
    --columns "pluginID,ip,pluginName,severity,pluginText" \\
    --filters '[{"filterName":"severity","operator":"=","value":"4"}]' \\
    --output log4j_critical.csv
"""

import argparse
import csv
import json
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
        description="Export Tenable SC plugin-text-search results to CSV (server-side filter)."
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
        help="Keyword to search for in plugin output text (required)",
    )
    p.add_argument(
        "--columns",
        default=os.getenv("TENABLE_COLUMNS", ""),
        help="Comma-separated columns to include in the response (optional)",
    )
    p.add_argument(
        "--filters",
        default=os.getenv("TENABLE_FILTERS", ""),
        help=(
            "JSON array of extra Tenable SC filters ANDed with the pluginText filter. "
            'Example: \'[{"filterName":"severity","operator":"=","value":"4"}]\''
        ),
    )
    p.add_argument(
        "--page-size",
        type=int,
        default=int(os.getenv("TENABLE_PAGE_SIZE", "1000")),
        help="Number of records per page (default: 1000)",
    )
    p.add_argument(
        "--output",
        default=os.getenv("TENABLE_OUTPUT", "plugin_text_search_results.csv"),
        help="Output CSV file path (default: plugin_text_search_results.csv)",
    )
    return p.parse_args()


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


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

def collect_fieldnames(all_rows: list[dict[str, Any]]) -> list[str]:
    """Return a stable, ordered list of all column names seen across all rows."""
    seen: dict[str, None] = {}
    for row in all_rows:
        for key in row:
            seen[key] = None
    return list(seen)


def flatten_values(row: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively flatten nested dicts (e.g. severity: {id, name}) to a string
    so they write cleanly to CSV.
    """
    flat: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, dict):
            flat[key] = json.dumps(value, ensure_ascii=False)
        elif isinstance(value, list):
            flat[key] = " | ".join(str(v) for v in value)
        else:
            flat[key] = value
    return flat


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    keyword = args.keyword.strip()
    if not keyword:
        print("ERROR: --keyword is required and must not be empty.", file=sys.stderr)
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

    print("Starting plugin-text-search export (server-side filter)")
    print(f"  Base URL : {args.base_url}")
    print(f"  Region   : {args.region}")
    print(f"  Keyword  : {keyword}")
    print(f"  Columns  : {columns or '(all)'}")
    print(f"  Filters  : {filters or '(none)'}")
    print(f"  Page size: {args.page_size}")
    print()

    while True:
        page_number += 1
        end_offset = start_offset + args.page_size
        print(
            f"  Fetching page {page_number}: offsets {start_offset}–{end_offset} ...",
            end=" ",
            flush=True,
        )

        try:
            data = fetch_page(
                session=session,
                base_url=args.base_url,
                region=args.region,
                keyword=keyword,
                columns=columns,
                filters=filters,
                start_offset=start_offset,
                page_size=args.page_size,
            )
        except requests.HTTPError as exc:
            print(
                f"\nERROR: HTTP {exc.response.status_code} — {exc.response.text}",
                file=sys.stderr,
            )
            sys.exit(1)
        except requests.RequestException as exc:
            print(f"\nERROR: Request failed — {exc}", file=sys.stderr)
            sys.exit(1)

        # totalRecords from SC is already the filtered count (server-side), so
        # it accurately reflects the total number of matching records.
        if total_records is None:
            total_records = data.get("totalRecords", 0)
            print(f"Total matching records reported by SC: {total_records}")

        page_results: list[dict] = data.get("results") or []
        returned = data.get("returnedRecords", len(page_results))

        for record in page_results:
            all_rows.append(flatten_values(record))

        print(
            f"records on page: {returned}, "
            f"total collected: {len(all_rows)}"
        )

        start_offset += args.page_size

        if total_records is not None and start_offset >= total_records:
            print(
                f"\n  All {total_records} matching records fetched across {page_number} page(s)."
            )
            break

        time.sleep(0.1)

    if not all_rows:
        print("\nNo matching records found. CSV will not be written.")
        sys.exit(0)

    # Determine CSV column order
    if columns:
        fieldnames = list(columns)
        extra = [f for f in collect_fieldnames(all_rows) if f not in fieldnames]
        fieldnames.extend(extra)
    else:
        fieldnames = collect_fieldnames(all_rows)

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
