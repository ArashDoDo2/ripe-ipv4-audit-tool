#!/usr/bin/env python3
"""
check_free_24s_org_id_cli_v6.py

Safe, parallel /24 auditor using RIPEstat routing-status,
retrieving the allocation list dynamically from a RIPE ORG-ID.

Changes in v6 (CLI Final):
1. Final CSV output is simplified to a single column:
   'Aggregated_Free_Block' containing only 'CIDR (IP_Count)'.
2. Commas in IP counts (e.g., 1,024) are removed to prevent CSV quoting issues.
3. Status and Notes columns are removed from the final output.

Usage:
    python3 check_free_24s_org_id_cli_v6.py > aggregated_free_blocks.csv
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import requests
import csv
import sys
import time

# ---- Configuration ----
RIPESTAT_URL = "https://stat.ripe.net/data/routing-status/data.json"
RDAP_URL_TEMPLATE = "https://rdap.db.ripe.net/entity/{org_id}"
MY_ASN = 31732  # <-- This is your Autonomous System Number (ASN)
MAX_WORKERS = 16
RETRIES = 2
RETRY_DELAY = 1.0  # seconds between retries on retries
REQUEST_TIMEOUT = 10.0  # seconds for each RIPEstat request


# ------------------------
# --- ORG-ID RDAP Functions ---
# ------------------------

def get_org_ipv4(org_id):
    """
    Retrieves a list of IPv4 CIDR ranges allocated to the given ORG-ID
    from RIPE NCC RDAP service.
    """
    url = RDAP_URL_TEMPLATE.format(org_id=org_id)
    print(f"INFO: Querying RIPE RDAP for ORG-ID '{org_id}' at {url}", file=sys.stderr)
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to retrieve data for ORG-ID {org_id}. {e}", file=sys.stderr)
        return []

    data = r.json()
    ipv4_list = []

    networks = data.get("networks", [])

    for net in networks:
        if "cidr0_cidrs" in net:
            for block in net.get("cidr0_cidrs", []):
                if "v4prefix" in block:
                    ipv4_list.append(f"{block['v4prefix']}/{block['length']}")

    if not ipv4_list and "cidr0_cidrs" in data:
        for block in data.get("cidr0_cidrs", []):
            if "v4prefix" in block:
                ipv4_list.append(f"{block['v4prefix']}/{block['length']}")

    return ipv4_list


# ------------------------
# --- /24 Audit Functions ---
# ------------------------

def generate_all_24s(alloc_list):
    """Expand allocations into list of /24 strings."""
    subnets = []
    for a in alloc_list:
        try:
            net = ipaddress.ip_network(a, strict=False)
        except Exception as e:
            print(f"WARNING: Skipping invalid allocation '{a}': {e}", file=sys.stderr)
            continue
        if net.version != 4:
            print(f"WARNING: Skipping non-IPv4 allocation '{a}'", file=sys.stderr)
            continue

        if net.prefixlen <= 24:
            if net.prefixlen == 24:
                subnets.append(str(net))
            else:
                subnets.extend(str(s) for s in net.subnets(new_prefix=24))
    return subnets


def query_ripestat(prefix):
    """Query RIPEstat routing-status for a prefix. Retries on transient errors."""
    params = {"resource": prefix}
    attempt = 0
    while attempt <= RETRIES:
        try:
            r = requests.get(RIPESTAT_URL, params=params, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            attempt += 1
            if attempt > RETRIES:
                print(f"ERROR: Failed to query RIPEstat for {prefix} after {RETRIES + 1} attempts.", file=sys.stderr)
                return {"error": str(e)}
            time.sleep(RETRY_DELAY)
    return {"error": "unknown"}


def analyze_prefix(prefix, ripestat_json):
    """
    Decide if prefix is candidate_free.
    Return tuple (prefix, status, notes) or None if not candidate_free.
    """
    if "error" in ripestat_json:
        return (prefix, "unknown", f"api_error: {ripestat_json['error']}")

    data = ripestat_json.get("data", {})
    origins = data.get("origins", []) or []
    more_specifics = data.get("more_specifics", []) or []
    less_specifics = data.get("less_specifics", []) or []

    # 1. Exact-match origins -> not free
    if origins:
        origin_asns = set()
        for o in origins:
            if isinstance(o, dict) and "origin" in o:
                origin_asns.add(int(o["origin"]))
            else:
                try:
                    origin_asns.add(int(o))
                except Exception:
                    pass
        return (prefix, "not_free", f"exact-origin: {sorted(origin_asns)}")

    # 2. More_specifics present -> not free
    if more_specifics:
        return (prefix, "not_free", f"more_specifics_present:{len(more_specifics)}")

    # 3. Check less_specifics for conflict (originating AS is NOT MY_ASN)
    non_my_asn_less = []
    for ls in less_specifics:
        origin = None
        if isinstance(ls, dict):
            origin = ls.get("origin")
        try:
            if origin is not None:
                origin_asn = int(origin)
                if origin_asn != MY_ASN:
                    non_my_asn_less.append(
                        (ls.get("prefix", "unknown") if isinstance(ls, dict) else str(ls), origin_asn))
            elif ls:
                non_my_asn_less.append(
                    (ls.get("prefix", "unknown") if isinstance(ls, dict) else str(ls), "unknown_origin"))
        except Exception:
            non_my_asn_less.append((ls.get("prefix", "unknown") if isinstance(ls, dict) else str(ls), "parse_error"))

    if non_my_asn_less:
        return (prefix, "not_free", f"covered_by_other_AS_less_specifics:{non_my_asn_less}")

    # 4. Candidate Free
    visibility = data.get("visibility", {}).get("v4", {}).get("ris_peers_seeing", 0)
    note = f"candidate_free; ris_peers_seeing={visibility}; less_specifics_count={len(less_specifics)}"

    return (prefix, "candidate_free", note)


def worker(prefix):
    """Worker to query + analyze a single prefix. Returns result tuple or None."""
    resp = query_ripestat(prefix)
    return analyze_prefix(prefix, resp)


def aggregate_cidrs(free_cidrs_24):
    """Aggregates a list of /24 CIDR strings into the largest possible blocks."""
    networks = []
    for cidr in free_cidrs_24:
        try:
            networks.append(ipaddress.ip_network(cidr))
        except ValueError:
            continue

    # ipaddress.collapse_addresses does the hard work of summarization
    aggregated = list(ipaddress.collapse_addresses(networks))
    return [str(net) for net in aggregated]


def main():
    print("\n=== IPv4 /24 Auditor using RIPE RDAP & RIPEstat (CLI) ===", file=sys.stderr)
    org_id = input("Enter ORG-ID (e.g., ORG-TA1-RIPE): ").strip()

    if not org_id:
        print("ERROR: ORG-ID cannot be empty. Exiting.", file=sys.stderr)
        sys.exit(1)

    # 1. Get ALLOCATIONS from RDAP
    allocations = get_org_ipv4(org_id)
    if not allocations:
        print(f"ERROR: Could not retrieve any IPv4 ranges for ORG-ID {org_id}. Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"\nINFO: Retrieved {len(allocations)} top-level allocations for {org_id}.", file=sys.stderr)

    # --- Display Allocations ---
    print("\n=== Retrieved Allocations (CIDR) ===", file=sys.stderr)
    for i, cidr in enumerate(allocations, 1):
        print(f"  {i}. {cidr}", file=sys.stderr)
    print("------------------------------------------", file=sys.stderr)

    # 2. Calculate Total IP Count
    total_ips = 0
    for cidr in allocations:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            total_ips += net.num_addresses
        except Exception:
            continue

    print(f"INFO: Total IP addresses covered by these allocations: {total_ips:,}", file=sys.stderr)

    # 3. Generate all /24 subnets
    subnets = generate_all_24s(allocations)
    print(f"INFO: Expanding to {len(subnets)} total /24 subnets for parallel audit.", file=sys.stderr)

    # 4. Parallel Audit and Collect Free /24s
    free_24s_list = []

    print("\nINFO: Starting RIPEstat concurrent audit...", file=sys.stderr)
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = {exe.submit(worker, p): p for p in subnets}
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as e:
                # Log worker error but do not add to free_24s list
                print(f"WARNING: Worker error for {futures[fut]}: {e}", file=sys.stderr)
                continue

            if not res:
                continue
            prefix, status, notes = res

            # Only collect the prefixes marked as candidate_free
            if status == "candidate_free":
                free_24s_list.append(prefix)

            # Optional: Print unknown status results to stderr during audit
            elif status == "unknown":
                print(f"WARNING: Audit failed for {prefix}: {notes}", file=sys.stderr)

    end_time = time.time()
    elapsed = end_time - start_time
    print(f"\nINFO: Audit completed in {elapsed:.2f} seconds. Found {len(free_24s_list)} candidate-free /24s.",
          file=sys.stderr)

    # 5. Aggregate the Free /24s
    if not free_24s_list:
        print("RESULT: No candidate-free blocks found. Exiting.", file=sys.stderr)
        sys.exit(0)

    print("INFO: Aggregating candidate-free /24s into largest possible CIDR blocks...", file=sys.stderr)
    aggregated_blocks = aggregate_cidrs(free_24s_list)

    # --- Final Output (Simplified CSV to stdout) ---
    writer = csv.writer(sys.stdout)

    # Header is now a single column
    writer.writerow(["Aggregated_Free_Block"])

    total_free_ips = 0
    for block in aggregated_blocks:
        # Calculate IPs in the aggregated block
        try:
            net = ipaddress.ip_network(block, strict=False)
            ip_count = net.num_addresses
            total_free_ips += ip_count
        except ValueError:
            ip_count = 0

        # Output format: CIDR (IP_Count)
        simple_output = f"{block} ({ip_count})"
        writer.writerow([simple_output])
        sys.stdout.flush()
    # ------------------------------------------------

    print(f"\nRESULT: Successfully generated {len(aggregated_blocks)} aggregated blocks.", file=sys.stderr)
    print(f"RESULT: Total free IP addresses available: {total_free_ips:,}.", file=sys.stderr)


if __name__ == "__main__":
    main()