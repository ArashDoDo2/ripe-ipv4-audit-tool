#!/usr/bin/env python3
"""
check_free_24s_org_id_cli_v28.py

Improvements over V27:
1. **Removed ASN Exception Logic:** The --my-asn argument and its related logic
   in analyze_prefix have been completely removed.
2. **Simplified Prefix Analysis:** Any presence of an Origin (exact match), More Specifics,
   or Less Specifics (Less Specifics now check ALL other routes, without self-exclusion)
   will result in 'not_free' status. This makes the check stricter and simpler.
3. **Configuration Cleanup:** Removed DEFAULT_MY_ASN.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import contextlib
import ipaddress
import requests
import csv
import sys
import time
import logging
from typing import List, Dict, Optional, Tuple, Any
from threading import Semaphore

# ---- Defaults / Configuration ----
DEFAULT_RIPESTAT_URL = "https://stat.ripe.net/data/routing-status/data.json"
DEFAULT_RDAP_URL_TEMPLATE = "https://rdap.db.ripe.net/entity/{org_id}"
# DEFAULT_MY_ASN = 31732  <-- REMOVED
DEFAULT_MAX_WORKERS = 16
DEFAULT_RETRIES = 2
DEFAULT_RETRY_DELAY = 1.0
DEFAULT_REQUEST_TIMEOUT = 10.0
DEFAULT_THROTTLE = 0.02  # seconds between requests per worker (soft throttle)
DEFAULT_ALLOC_FALLBACK = 8
MAX_ALLOC_LINE_LENGTH = 100

# ---- Globals (needed for passing worker context to analyze_prefix's hierarchical lookup) ---
ALLOCATION_MAP: Dict[str, int] = {}
RIPE_CACHE: Dict[str, dict] = {}
global_session: Optional[requests.Session] = None
global_semaphore: Optional[Semaphore] = None
global_throttle: float = DEFAULT_THROTTLE
global_retries: int = DEFAULT_RETRIES
global_retry_delay: float = DEFAULT_RETRY_DELAY
global_rdap_data: dict = {}
global_cidr_network_data: Dict[str, dict] = {}  # Key: CIDR string, Value: Network object data

# ---- Logging setup ----
logger = logging.getLogger("check_free_24s")
handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter("%(levelname)s: %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)  # Default level set to INFO


def parse_args():
    p = argparse.ArgumentParser(description="IPv4 /24 Auditor using RIPE RDAP & RIPEstat (CLI V28 - No ASN Exclusion)")
    p.add_argument("--org-id", "-o", help="ORG-ID (eg ORG-TA1-RIPE). If omitted will prompt.")
    # p.add_argument("--my-asn", type=int, default=DEFAULT_MY_ASN, help="Your ASN to treat as 'owned' in checks.") <-- REMOVED
    p.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Concurrent worker threads.")
    p.add_argument("--retries", type=float, default=DEFAULT_RETRIES, help="Retry attempts for HTTP calls.")
    p.add_argument("--retry-delay", type=float, default=DEFAULT_RETRY_DELAY, help="Base retry delay (secs).")
    p.add_argument("--timeout", type=float, default=DEFAULT_REQUEST_TIMEOUT, help="HTTP request timeout (secs).")
    p.add_argument("--throttle", type=float, default=DEFAULT_THROTTLE, help="Per-request soft throttle (secs).")
    p.add_argument("--output", "-f", default=None, help="Output CSV file (defaults to stdout).")
    p.add_argument("--debug", action="store_true", help="Enable debug logging.")
    return p.parse_args()


# ---- Utility Functions (RDAP, RIPEstat, IP tools) - Mostly Unchanged ----

def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "check_free_24s_cli_v28/1.0 (+https://example)"})
    return s


def extract_date_from_events(data: dict, event_type: str) -> Optional[str]:
    events = data.get("events", [])
    for event in events:
        if event.get("eventAction") == event_type:
            timestamp = event.get("eventDate")
            if timestamp:
                return get_date_only(timestamp)
    return None


def rdap_get_ipv4_from_org(session: requests.Session, org_id: str, timeout: float, retries: int, retry_delay: float) -> \
List[str]:
    global global_rdap_data, global_cidr_network_data
    url = DEFAULT_RDAP_URL_TEMPLATE.format(org_id=org_id)
    logger.info(f"Querying RIPE RDAP for ORG-ID '{org_id}' at {url}")
    attempt = 0
    while True:
        try:
            r = session.get(url, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            global_rdap_data = data
            ipv4_list = []
            cidr_network_map: Dict[str, dict] = {}

            networks = data.get("networks") or []
            for net in networks:
                if isinstance(net, dict):
                    cidrs: List[Any] = []

                    if 'cidr0_cidrs' in net and isinstance(net['cidr0_cidrs'], list):
                        cidrs.extend(net['cidr0_cidrs'])

                    for block_info in cidrs:
                        if isinstance(block_info, dict) and "v4prefix" in block_info and "length" in block_info:
                            cidr = f"{block_info['v4prefix']}/{block_info['length']}"
                            try:
                                netobj = ipaddress.ip_network(cidr, strict=False)
                                if netobj.version == 4:
                                    ipv4_list.append(cidr)
                                    cidr_network_map[cidr] = net
                            except Exception:
                                pass

            valid_ipv4 = []
            for cidr in sorted(set(ipv4_list)):
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if net.version == 4:
                        valid_ipv4.append(str(net))
                except Exception:
                    logger.debug(f"Skipping invalid RDAP CIDR '{cidr}'")

            global_cidr_network_data = {cidr: cidr_network_map[cidr] for cidr in valid_ipv4 if cidr in cidr_network_map}
            return valid_ipv4

        except requests.RequestException as e:
            attempt += 1
            if attempt > retries:
                logger.error(f"Failed to retrieve RDAP data for {org_id} after {retries + 1} attempts: {e}")
                return []
            backoff = retry_delay * (2 ** (attempt - 1))
            logger.warning(
                f"RDAP fetch failed (attempt {attempt}/{retries + 1}). Backing off {backoff:.1f}s. Error: {e}")
            time.sleep(backoff)


def query_ripestat(session: requests.Session, prefix: str, timeout: float, retries: int, retry_delay: float,
                   throttle: float, semaphore: Semaphore) -> dict:
    global RIPE_CACHE
    if prefix in RIPE_CACHE:
        return RIPE_CACHE[prefix]

    params = {"resource": prefix}
    url = DEFAULT_RIPESTAT_URL
    attempt = 0
    while True:
        try:
            with semaphore:
                if throttle:
                    time.sleep(throttle)
                r = session.get(url, params=params, timeout=timeout)
            r.raise_for_status()
            result = r.json()
            RIPE_CACHE[prefix] = result
            return result
        except requests.RequestException as e:
            attempt += 1
            if attempt > retries:
                logger.error(f"Failed to query RIPEstat for {prefix} after {retries + 1} attempts. Last error: {e}")
                return {"error": str(e)}
            backoff = retry_delay * (2 ** (attempt - 1))
            logger.debug(
                f"RIPEstat query failed for {prefix} (attempt {attempt}/{retries + 1}). Backing off {backoff:.1f}s.")
            time.sleep(backoff)


def get_last_seen_time(ripestat_json: dict) -> Optional[str]:
    if not ripestat_json or "error" in ripestat_json:
        return None
    return ripestat_json.get("data", {}).get("last_seen", {}).get("time")


def get_date_only(full_timestamp: Optional[str]) -> Optional[str]:
    if not full_timestamp:
        return None
    if "T" in full_timestamp:
        return full_timestamp.split("T")[0]
    if " " in full_timestamp:
        return full_timestamp.split(" ")[0]
    if len(full_timestamp) >= 10:
        return full_timestamp[:10]
    return full_timestamp


def map_24s_to_allocations(alloc_list: List[str]) -> None:
    global ALLOCATION_MAP
    allocation_map: Dict[str, int] = {}
    for alloc_cidr in alloc_list:
        try:
            net = ipaddress.ip_network(alloc_cidr, strict=False)
            if net.version != 4:
                continue
            if net.prefixlen <= 24:
                if net.prefixlen == 24:
                    allocation_map[str(net)] = net.prefixlen
                else:
                    for sub_24 in net.subnets(new_prefix=24):
                        sub = str(sub_24)
                        if sub not in allocation_map or net.prefixlen < allocation_map[sub]:
                            allocation_map[sub] = net.prefixlen
        except Exception as e:
            logger.debug(f"Skipping invalid allocation '{alloc_cidr}' during mapping: {e}")
    ALLOCATION_MAP = allocation_map


def generate_all_24s(alloc_list: List[str]) -> List[str]:
    subnets: List[str] = []
    for a in alloc_list:
        try:
            net = ipaddress.ip_network(a, strict=False)
            if net.version != 4:
                logger.debug(f"Skipping non-IPv4 allocation '{a}'")
                continue
        except Exception as e:
            logger.debug(f"Skipping invalid allocation '{a}': {e}")
            continue
        if net.prefixlen <= 24:
            if net.prefixlen == 24:
                subnets.append(str(net))
            else:
                subnets.extend(str(s) for s in net.subnets(new_prefix=24))
    return subnets


# V28: Removed my_asn argument
def analyze_prefix(prefix: str, ripestat_json: dict) -> Tuple[str, str, str, Optional[str]]:
    global global_session, global_semaphore, global_throttle, global_retries, global_retry_delay

    if "error" in ripestat_json:
        return prefix, "unknown", f"api_error: {ripestat_json.get('error')}", None

    data = ripestat_json.get("data", {})
    origins = data.get("origins", []) or []
    more_specifics = data.get("more_specifics", []) or []
    less_specifics = data.get("less_specifics", []) or []

    current_last_seen = get_last_seen_time(ripestat_json)

    # --- Free/Not-Free Determination (Simplified for V28) ---
    if origins:
        origin_asns = set()
        for o in origins:
            if isinstance(o, dict) and "origin" in o:
                try:
                    origin_asns.add(int(o["origin"]))
                except Exception:
                    pass
            else:
                try:
                    origin_asns.add(int(o))
                except Exception:
                    pass
        # Case 1: Exact match route exists (always not_free)
        return prefix, "not_free", f"exact-origin: {sorted(origin_asns)}", None

    if more_specifics:
        # Case 2: More specific routes exist (always not_free)
        return prefix, "not_free", f"more_specifics_present:{len(more_specifics)}", None

    if less_specifics:
        # Case 3 (V28 Logic): Any less specific route exists (always not_free)
        # Note: We still gather the origin info for the error message, but the check is simpler.
        less_specific_info = []
        for ls in less_specifics:
            origin = ls.get("origin") if isinstance(ls, dict) else "unknown"
            ls_prefix = ls.get("prefix", "unknown") if isinstance(ls, dict) else str(ls)
            less_specific_info.append((ls_prefix, origin))

        return prefix, "not_free", f"covered_by_less_specifics:{less_specific_info}", None

    # --- Last Seen Check (Unchanged) ---
    target_len = ALLOCATION_MAP.get(prefix, DEFAULT_ALLOC_FALLBACK)
    best_last_seen = current_last_seen

    try:
        net_24 = ipaddress.ip_network(prefix, strict=False)
        for parent_length in range(23, target_len - 1, -1):
            parent_net = net_24.supernet(new_prefix=parent_length)
            parent_prefix = str(parent_net)

            parent_resp = query_ripestat(
                global_session, parent_prefix, DEFAULT_REQUEST_TIMEOUT, global_retries,
                global_retry_delay, global_throttle, global_semaphore
            )

            last_seen_parent = get_last_seen_time(parent_resp)

            if last_seen_parent:
                if best_last_seen is None or last_seen_parent > best_last_seen:
                    best_last_seen = last_seen_parent
                    logger.debug(f"Updated Max Last Seen for {prefix} from parent {parent_prefix} to {best_last_seen}")

    except Exception as e:
        logger.debug(f"Targeted hierarchical check failed for {prefix}: {e}")

    # Case 4: Nothing is visible (candidate_free)
    visibility = data.get("visibility", {}).get("v4", {}).get("ris_peers_seeing", 0)
    note = f"candidate_free; ris_peers_seeing={visibility}"

    return prefix, "candidate_free", note, best_last_seen


# Worker uses closure to access configuration
# V28: Removed my_asn argument
def make_worker(session: requests.Session, timeout: float, retries: int, retry_delay: float, throttle: float,
                semaphore: Semaphore):
    def worker(prefix: str):
        # Note: analyze_prefix no longer needs my_asn
        resp = query_ripestat(session, prefix, timeout, retries, retry_delay, throttle, semaphore)
        return analyze_prefix(prefix, resp)

    return worker


def aggregate_cidrs(free_cidrs_24: List[str]) -> List[str]:
    networks = []
    for cidr in free_cidrs_24:
        try:
            networks.append(ipaddress.ip_network(cidr))
        except Exception:
            continue
    aggregated = list(ipaddress.collapse_addresses(networks))
    return [str(net) for net in aggregated]


def format_allocation_list_v27(allocations: List[str]) -> List[str]:
    """Formats the list of allocations with their registration dates into a list of strings (one per CIDR)."""
    global global_cidr_network_data
    output_lines = []

    for block in allocations:
        net_data = global_cidr_network_data.get(block, {})
        reg_date = extract_date_from_events(net_data, "registration")
        if not reg_date:
            reg_date = extract_date_from_events(net_data, "creation")

        date_str = f"({reg_date})" if reg_date else "(تاریخ نامشخص)"

        output_lines.append(f"* {block} {date_str}")

    return output_lines


# --- Main ---
def main():
    global global_session, global_semaphore, global_throttle, global_retries, global_retry_delay, DEFAULT_REQUEST_TIMEOUT
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    org_id = args.org_id
    if not org_id:
        try:
            org_id = input("Enter ORG-ID (e.g., ORG-TA1-RIPE): ").strip()
        except KeyboardInterrupt:
            logger.error("Interrupted by کاربر. Exiting.")
            sys.exit(1)
    if not org_id:
        logger.error("ORG-ID cannot be empty. Exiting.")
        sys.exit(1)

    DEFAULT_REQUEST_TIMEOUT = args.timeout
    global_retries = int(args.retries)
    global_retry_delay = args.retry_delay
    global_throttle = args.throttle

    with make_session() as session:
        global_session = session
        max_workers = max(1, args.max_workers)
        semaphore = Semaphore(max_workers)
        global_semaphore = semaphore

        print(f"\n=======================================================", file=sys.stderr)
        print(f"=== حسابرسی آدرس‌های IPv4 (نسخه ۲۸) - ORG: {org_id} ===", file=sys.stderr)
        print(f"=======================================================\n", file=sys.stderr)

        # 1. Get ALLOCATIONS from RDAP
        allocations = rdap_get_ipv4_from_org(session, org_id, DEFAULT_REQUEST_TIMEOUT, global_retries, global_retry_delay)
        if not allocations:
            logger.error(f"Could not retrieve any IPv4 ranges for ORG-ID {org_id}. Exiting.")
            sys.exit(1)

        logger.debug(f"Retrieved {len(allocations)} top-level allocations for {org_id}.")

        # 2. Display Allocation Summary
        print("## 🌐 خلاصه واگذاری‌های اصلی (RDAP)", file=sys.stderr)
        print("-------------------------------------------------------", file=sys.stderr)

        registration_date = extract_date_from_events(global_rdap_data, "registration")
        last_changed_date = extract_date_from_events(global_rdap_data, "last changed")

        print(f"* واگذاری اولیه ORG-ID: **{registration_date if registration_date else 'نامشخص'}**", file=sys.stderr)
        print(f"* آخرین تغییر ثبت ORG-ID: **{last_changed_date if last_changed_date else 'نامشخص'}**", file=sys.stderr)
        print(f"* تعداد بلاک‌های واگذار شده: **{len(allocations)}**", file=sys.stderr)

        formatted_list_lines = format_allocation_list_v27(allocations)
        print(f"* لیست بلاک‌ها (CIDR و تاریخ واگذاری اولیه):", file=sys.stderr)

        for line in formatted_list_lines:
            print(f"  {line}", file=sys.stderr)

        print("-" * 55 + "\n", file=sys.stderr)

        # 3. Map /24s and Prepare for Audit
        map_24s_to_allocations(allocations)
        subnets = generate_all_24s(allocations)
        logger.debug(f"Mapped {len(ALLOCATION_MAP)} /24 subnets. Expanding to {len(subnets)} total /24 subnets.")

        free_24s_list: List[str] = []
        free_24_last_seen: Dict[str, str] = {}

        logger.info("Starting RIPEstat concurrent audit...")
        start_time = time.time()

        # V28: Worker creation no longer needs my_asn
        worker = make_worker(session, DEFAULT_REQUEST_TIMEOUT, global_retries, global_retry_delay, args.throttle, semaphore)

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as exe:
                futures = {exe.submit(worker, p): p for p in subnets}
                total_subnets = len(subnets)
                processed_count = 0
                for fut in as_completed(futures):
                    processed_count += 1
                    if processed_count % 50 == 0:
                        logger.debug(f"Progress: {processed_count}/{total_subnets} processed.")
                    try:
                        # V28: worker result format is now different (only 4 elements)
                        prefix, status, notes, best_last_seen_time = fut.result()
                    except KeyboardInterrupt:
                        logger.error("Interrupted by کاربر. Attempting to shut down workers.")
                        raise
                    except Exception as e:
                        logger.warning(f"Worker error for {futures[fut]}: {e}")
                        continue

                    if status == "candidate_free":
                        free_24s_list.append(prefix)
                        if best_last_seen_time:
                            free_24_last_seen[prefix] = best_last_seen_time
        except KeyboardInterrupt:
            logger.error("Interrupted by کاربر. Exiting.")
            sys.exit(1)

        elapsed = time.time() - start_time
        logger.info(f"Audit completed in {elapsed:.2f} seconds. Found {len(free_24s_list)} candidate-free /24s.")

        if not free_24s_list:
            logger.info("No candidate-free blocks found. Exiting.")
            sys.exit(0)

        aggregated_blocks = aggregate_cidrs(free_24s_list)

        # 4. Final Output to CSV (stdout or file)
        with contextlib.ExitStack() as stack:
            out_f = sys.stdout
            if args.output:
                try:
                    out_f = stack.enter_context(open(args.output, "w", newline="", encoding="utf-8"))
                except IOError as e:
                    logger.error(f"Failed to open output file {args.output}: {e}")
                    sys.exit(1)

            writer = csv.writer(out_f, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(["Aggregated_Free_Block", "Max_Last_Seen_Date", "Last_Seen_Details"])

            total_free_ips = 0

            for block in aggregated_blocks:
                try:
                    net = ipaddress.ip_network(block, strict=False)
                except ValueError:
                    logger.warning(f"Skipping invalid aggregated block '{block}' in output.")
                    continue

                ip_count = net.num_addresses
                simple_output = f"{block} ({ip_count})"
                sub_24s = [str(s) for s in net.subnets(new_prefix=24)]
                total_free_ips += ip_count

                # --- Aggregation logic (Unchanged) ---
                grouped_24s: Dict[Optional[str], List[ipaddress.IPv4Network]] = {}
                all_dates_in_block = []
                allocation_boundary_len = ALLOCATION_MAP.get(sub_24s[0],
                                                             DEFAULT_ALLOC_FALLBACK) if sub_24s else DEFAULT_ALLOC_FALLBACK

                for sub_24 in sub_24s:
                    if sub_24 in free_24_last_seen:
                        last_seen_date = get_date_only(free_24_last_seen[sub_24])
                        if last_seen_date:
                            all_dates_in_block.append(last_seen_date)
                        group_key = last_seen_date
                        grouped_24s.setdefault(group_key, []).append(ipaddress.ip_network(sub_24))

                max_last_seen_date = "N/A"
                if all_dates_in_block:
                    max_last_seen_date = sorted(all_dates_in_block)[-1]

                last_seen_details = "No routing data found."

                if grouped_24s:
                    header = f"Alloc Boundary /{allocation_boundary_len}"
                    is_single_group = len(grouped_24s) == 1
                    if is_single_group:
                        date = next(iter(grouped_24s.keys()))
                        date_label = f"Date: {date}" if date else "Date: N/A"
                        if net.prefixlen == 24:
                            last_seen_details = f"{header}: {date_label}"
                        else:
                            last_seen_details = f"{header}: All /24s ({date_label})"
                    else:
                        partial_entries = []
                        for date, net_list in grouped_24s.items():
                            aggregated_partials = list(ipaddress.collapse_addresses(net_list))
                            partial_blocks_str = ", ".join(str(p) for p in aggregated_partials)
                            date_label = f"(Date: {date})" if date else "(Date: N/A)"
                            entry = f"{partial_blocks_str} {date_label}"
                            partial_entries.append(entry)
                        entries_str = " | ".join(partial_entries)
                        last_seen_details = f"{header}: {entries_str}"
                # --- End Aggregation Logic ---

                writer.writerow([simple_output, max_last_seen_date, last_seen_details])

        # 5. Final Summary
        print("\n## 📊 خلاصه نهایی نتایج", file=sys.stderr)
        print("-------------------------------------------------------", file=sys.stderr)
        print(f"* تعداد بلاک‌های تجمیع شده نامزد آزاد: **{len(aggregated_blocks)}**", file=sys.stderr)
        print(f"* مجموع آدرس‌های IP نامزد آزاد (Candidate Free): **{total_free_ips}**", file=sys.stderr)
        print("=======================================================\n", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
