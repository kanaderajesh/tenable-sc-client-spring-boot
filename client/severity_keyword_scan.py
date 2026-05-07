#!/usr/bin/env python3
"""
Scan vulnerabilities by severity for keywords in plugin output text.

For each severity level (4=Critical, 3=High, 2=Medium, 1=Low) the script
pages through all vulnerability records using POST /api/v1/vulnerabilities/filter.
Each record's pluginText is searched client-side (case-insensitive, single pass)
against every keyword from the keywords file. Matching records are written to a
single CSV file with a 'matchedKeywords' column and a 'severityLabel' column.

Results are flushed to CSV after every page so nothing is lost on interruption
or exception. On KeyboardInterrupt the script saves whatever was collected and
exits cleanly.

Usage
-----
  python severity_keyword_scan.py [OPTIONS]

Options
-------
  --base-url       Base URL of the Spring Boot API      (default: http://localhost:8080)
  --region         Tenable SC region name                (required)
  --keywords-file  Path to file with one keyword per line (required)
  --columns        Comma-separated columns to request from SC and include in the CSV.
                   pluginText is always fetched for matching but only appears in
                   the CSV when explicitly listed here.
                   (default: pluginID,ip,pluginName,severity,pluginText)
  --severities     Comma-separated severity levels to scan  (default: 4,3,2,1)
  --page-size      Records fetched per API call              (default: 1000)
  --output         Output CSV file path                      (default: severity_keyword_results.csv)

Keywords file format
--------------------
  One keyword per line. Blank lines and lines starting with '#' are ignored.

  Example keywords.txt:
    # CVEs
    CVE-2021-44228
    log4j
    heartbleed

Environment variables (override defaults, overridden by CLI flags)
------------------------------------------------------------------
  TENABLE_BASE_URL, TENABLE_REGION, TENABLE_KEYWORDS_FILE,
  TENABLE_COLUMNS, TENABLE_SEVERITIES, TENABLE_PAGE_SIZE, TENABLE_OUTPUT

Examples
--------
  # Scan critical and high vulns for log4j-related keywords
  python severity_keyword_scan.py \\
    --region APAC \\
    --keywords-file keywords.txt \\
    --severities 4,3 \\
    --columns "pluginID,ip,pluginName,severity,pluginText" \\
    --output critical_high_matches.csv

  # Scan all severity levels
  python severity_keyword_scan.py \\
    --region APAC \\
    --keywords-file keywords.txt \\
    --output all_severity_matches.csv
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

# Maps severity integer value to a human-readable label
SEVERITY_LABELS: dict[str, str] = {
    "4": "Critical",
    "3": "High",
    "2": "Medium",
    "1": "Low",
    "0": "Info",
}

DEFAULT_COLUMNS = "pluginID,ip,pluginName,severity,pluginText"


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Scan Tenable SC vulnerabilities by severity for keywords in "
            "plugin output text and export matching records to CSV."
        )
    )
    p.add_argument(
        "--base-url",
        default=os.getenv("TENABLE_BASE_URL", "http://localhost:8080"),
        help="Spring Boot API base URL (default: http://localhost:8080)",
    )
    p.add_argument(
        "--region",
        default=os.getenv("TENABLE_REGION", ""),
        help="Tenable SC region name (e.g. APAC, EMEA, AMER) — required",
    )
    p.add_argument(
        "--keywords-file",
        default=os.getenv("TENABLE_KEYWORDS_FILE", ""),
        metavar="FILE",
        help="Path to a file with one keyword per line (required)",
    )
    p.add_argument(
        "--columns",
        default=os.getenv("TENABLE_COLUMNS", DEFAULT_COLUMNS),
        help=f"Comma-separated columns to request and include in CSV (default: {DEFAULT_COLUMNS})",
    )
    p.add_argument(
        "--severities",
        default=os.getenv("TENABLE_SEVERITIES", "4,3,2,1"),
        help="Comma-separated severity levels to scan in order (default: 4,3,2,1)",
    )
    p.add_argument(
        "--page-size",
        type=int,
        default=int(os.getenv("TENABLE_PAGE_SIZE", "1000")),
        help="Records per page (default: 1000)",
    )
    p.add_argument(
        "--output",
        default=os.getenv("TENABLE_OUTPUT", "severity_keyword_results.csv"),
        help="Output CSV file path (default: severity_keyword_results.csv)",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Keyword loading
# ---------------------------------------------------------------------------

def load_keywords(path: str) -> list[str]:
    """Load keywords from a file, one per line. Blank lines and '#' comments ignored."""
    if not os.path.isfile(path):
        print(f"ERROR: --keywords-file '{path}' not found.", file=sys.stderr)
        sys.exit(1)
    keywords: list[str] = []
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
    severity: str,
    sc_columns: list[str],
    start_offset: int,
    page_size: int,
) -> dict[str, Any]:
    """Fetch one page of vulnerabilities filtered to a specific severity."""
    url = f"{base_url.rstrip('/')}/api/v1/vulnerabilities/filter"
    params = {
        "region": region,
        "startOffset": start_offset,
        "endOffset": start_offset + page_size,
    }
    body: list[dict] = [
        {"filterName": "severity", "operator": "=", "value": severity}
    ]
    if sc_columns:
        params["columns"] = sc_columns  # passed as repeated query params

    response = session.post(url, params=params, json=body, timeout=120)
    response.raise_for_status()
    return response.json()


# ---------------------------------------------------------------------------
# Keyword matching
# ---------------------------------------------------------------------------

def match_keywords(
    record: dict[str, Any],
    original_keywords: list[str],
    lower_keywords: list[str],
) -> list[str]:
    """
    Return the subset of keywords found in the record's pluginText.
    pluginText is lowercased once; all keywords are scanned in a single pass.
    """
    plugin_text = record.get("pluginText")
    if not plugin_text:
        return []
    lower_text = str(plugin_text).lower()
    return [
        original_keywords[i]
        for i, lk in enumerate(lower_keywords)
        if lk in lower_text
    ]


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

def build_fieldnames(columns: list[str], include_plugin_text: bool) -> list[str]:
    """
    Return the ordered CSV column list:
      severityLabel | requested columns (minus pluginText if not requested) | matchedKeywords
    """
    fields = ["severityLabel"] + list(columns)
    if not include_plugin_text and "pluginText" in fields:
        fields.remove("pluginText")
    if "matchedKeywords" not in fields:
        fields.append("matchedKeywords")
    return fields


def flatten_record(
    record: dict[str, Any],
    severity_label: str,
    matched: list[str],
) -> dict[str, Any]:
    """Flatten a raw SC record into a CSV row dict."""
    row: dict[str, Any] = {"severityLabel": severity_label}
    for key, value in record.items():
        if isinstance(value, dict):
            row[key] = json.dumps(value, ensure_ascii=False)
        elif isinstance(value, list):
            row[key] = " | ".join(str(v) for v in value)
        else:
            row[key] = value
    row["matchedKeywords"] = " | ".join(matched)
    return row


def write_rows(
    rows: list[dict[str, Any]],
    path: str,
    fieldnames: list[str],
    mode: str,
    write_header: bool,
) -> None:
    """Append or write rows to a CSV file."""
    with open(path, mode, newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=fieldnames,
            extrasaction="ignore",
            quoting=csv.QUOTE_MINIMAL,
        )
        if write_header:
            writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Per-severity scan
# ---------------------------------------------------------------------------

def scan_severity(
    session: requests.Session,
    base_url: str,
    region: str,
    severity: str,
    sc_columns: list[str],
    original_keywords: list[str],
    lower_keywords: list[str],
    fieldnames: list[str],
    output_path: str,
    page_size: int,
    first_write: bool,
    counters: dict[str, int],
) -> tuple[int, bool]:
    """
    Page through all vulnerabilities for one severity level, match keywords
    client-side, and flush matching rows to CSV after every page.

    counters is a shared dict with keys 'records_processed' and 'total_matched'
    that accumulates grand totals across all severity levels so each page line
    can show overall progress.

    Returns (severity_matched, was_interrupted).
    """
    label = SEVERITY_LABELS.get(severity, f"Severity-{severity}")
    start_offset = 0
    total_records: int | None = None
    page_number = 0
    severity_matched = 0
    pending_rows: list[dict[str, Any]] = []

    def flush_pending() -> None:
        nonlocal first_write, pending_rows
        if not pending_rows:
            return
        write_rows(pending_rows, output_path, fieldnames,
                   "w" if first_write else "a", first_write)
        first_write = False
        pending_rows = []

    try:
        while True:
            page_number += 1
            total_pages = math.ceil(total_records / page_size) if total_records else "?"
            end_offset = (
                min(start_offset + page_size, total_records)
                if total_records else start_offset + page_size
            )

            print(
                f"    Page {page_number}/{total_pages} | "
                f"[{label}] records {start_offset + 1}–{end_offset} of {total_records or '?'} | "
                f"fetching ...",
                end=" ",
                flush=True,
            )

            try:
                data = fetch_page(
                    session=session,
                    base_url=base_url,
                    region=region,
                    severity=severity,
                    sc_columns=sc_columns,
                    start_offset=start_offset,
                    page_size=page_size,
                )
            except requests.HTTPError as exc:
                print(
                    f"\n  ERROR: HTTP {exc.response.status_code} — {exc.response.text}",
                    file=sys.stderr,
                )
                flush_pending()
                raise
            except requests.RequestException as exc:
                print(f"\n  ERROR: Request failed — {exc}", file=sys.stderr)
                flush_pending()
                raise

            if total_records is None:
                total_records = data.get("totalRecords", 0)
                total_pages = math.ceil(total_records / page_size) if total_records else 1
                end_offset = min(start_offset + page_size, total_records)

            page_results: list[dict] = data.get("results") or []
            matched_this_page = 0

            for record in page_results:
                matched = match_keywords(record, original_keywords, lower_keywords)
                if matched:
                    pending_rows.append(flatten_record(record, label, matched))
                    matched_this_page += 1

            severity_matched += matched_this_page

            # Update shared grand-total counters
            counters["records_processed"] += len(page_results)
            counters["total_matched"] += matched_this_page

            # Flush this page's matches immediately so nothing is lost
            flush_pending()

            processed = min(start_offset + page_size, total_records) if total_records else end_offset
            sev_pct = int(processed / total_records * 100) if total_records else 0
            print(
                f"done | "
                f"this page: {len(page_results)} records / {matched_this_page} matched | "
                f"[{label}] progress: {processed}/{total_records} ({sev_pct}%) — "
                f"{severity_matched} matched | "
                f"OVERALL: {counters['records_processed']} processed / "
                f"{counters['total_matched']} matched"
            )

            start_offset += page_size
            if total_records is not None and start_offset >= total_records:
                print(
                    f"    Completed [{label}]: {total_records} records scanned, "
                    f"{severity_matched} keyword matches found. "
                    f"| Overall so far: {counters['records_processed']} records / "
                    f"{counters['total_matched']} matched"
                )
                break

            time.sleep(0.1)

    except KeyboardInterrupt:
        flush_pending()
        print(
            f"\n  Interrupted during [{label}] after {page_number} page(s). "
            f"Overall: {counters['records_processed']} records processed, "
            f"{counters['total_matched']} match(es) saved.",
            flush=True,
        )
        return severity_matched, True

    return severity_matched, False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    if not args.region.strip():
        print("ERROR: --region is required.", file=sys.stderr)
        sys.exit(1)

    if not args.keywords_file.strip():
        print("ERROR: --keywords-file is required.", file=sys.stderr)
        sys.exit(1)

    keywords = load_keywords(args.keywords_file.strip())
    if not keywords:
        print("ERROR: Keywords file is empty or contains only comments.", file=sys.stderr)
        sys.exit(1)

    # Pre-lowercase keywords for fast per-record matching
    lower_keywords = [kw.lower() for kw in keywords]

    # Parse requested columns; always add pluginText for matching if absent
    requested_columns = [c.strip() for c in args.columns.split(",") if c.strip()]
    include_plugin_text_in_csv = "pluginText" in requested_columns
    sc_columns = list(requested_columns)
    if "pluginText" not in sc_columns:
        sc_columns.append("pluginText")  # needed for matching, excluded from CSV output

    # Parse severities
    severities = [s.strip() for s in args.severities.split(",") if s.strip()]
    invalid = [s for s in severities if s not in SEVERITY_LABELS]
    if invalid:
        print(f"ERROR: Unknown severity value(s): {invalid}. Use 0–4.", file=sys.stderr)
        sys.exit(1)

    fieldnames = build_fieldnames(requested_columns, include_plugin_text_in_csv)

    print("Severity keyword scan")
    print(f"  Base URL      : {args.base_url}")
    print(f"  Region        : {args.region}")
    print(f"  Keywords      : {len(keywords)} loaded from {args.keywords_file}")
    print(f"  Severities    : {[f'{s}={SEVERITY_LABELS[s]}' for s in severities]}")
    print(f"  Columns       : {requested_columns}")
    print(f"  Page size     : {args.page_size}")
    print(f"  Output        : {args.output}")
    print()

    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})

    grand_total = 0
    first_write = True  # tracks whether we've written the header yet
    counters: dict[str, int] = {"records_processed": 0, "total_matched": 0}

    try:
        for sev in severities:
            label = SEVERITY_LABELS[sev]
            print(f"[Severity {sev} — {label}]")
            matched, interrupted = scan_severity(
                session=session,
                base_url=args.base_url,
                region=args.region,
                severity=sev,
                sc_columns=sc_columns,
                original_keywords=keywords,
                lower_keywords=lower_keywords,
                fieldnames=fieldnames,
                output_path=args.output,
                page_size=args.page_size,
                first_write=first_write,
                counters=counters,
            )
            grand_total += matched
            # Update first_write: once any rows have been written the file exists
            if matched > 0:
                first_write = False
            print(f"  -> {matched} match(es) for severity {sev} ({label})\n")

            if interrupted:
                print(
                    f"Scan interrupted. {grand_total} total match(es) saved to {args.output} | "
                    f"Overall: {counters['records_processed']} records processed"
                )
                sys.exit(130)

    except KeyboardInterrupt:
        print(
            f"\nInterrupted between severity levels. "
            f"{grand_total} total match(es) saved to {args.output} | "
            f"Overall: {counters['records_processed']} records processed"
        )
        sys.exit(130)
    except Exception as exc:
        print(f"\nUnexpected error: {exc}", file=sys.stderr)
        print(
            f"{grand_total} match(es) collected so far have been saved to {args.output} | "
            f"Overall: {counters['records_processed']} records processed"
        )
        raise

    if grand_total == 0:
        print("No keyword matches found across any severity level.")
    else:
        print(f"Done. {grand_total} total match(es) written to: {args.output}")


if __name__ == "__main__":
    main()
