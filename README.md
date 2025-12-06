# 🔎 RIPE IPv4 Audit Tool (CLI)

## 🌟 Overview

**`ripe-ipv4-audit-tool`** is a fast, concurrent Python CLI utility designed to audit large IPv4 address allocations registered under a specific RIPE **ORG-ID**.

The tool queries RIPE RDAP to retrieve all assigned CIDR blocks and then uses **RIPEstat's Routing Status API** to determine which individual `/24` subnets are currently **Candidate Free** (i.e., not actively advertised in the global BGP routing table) and therefore potentially available for use.

This tool is invaluable for LIRs managing large address space and needing to quickly identify unused or "dark" space for reassignment.

## ✨ Features

* **RDAP Integration:** Retrieves all IPv4 allocation blocks associated with a given `ORG-ID`.
* **Concurrency:** Uses multi-threading to check the routing status of hundreds of `/24` subnets quickly.
* **Stricter Routing Logic (V28):** A block is considered **NOT FREE** if *any* exact route, more specific route, or less specific (covering) route is currently visible in BGP.
* **Historical Check:** Performs hierarchical lookups on parent blocks to report the **maximum last-seen date**, giving a better indication of how long the space has been inactive.
* **Aggregated Output:** Collapses consecutive free `/24`s into larger CIDR blocks (e.g., `/22`, `/21`) for easy overview.
* **Detailed Summary:** Provides registration dates and allocation lists directly from RDAP in the console.
* **CSV Output:** Exports detailed results to a structured CSV file.

## 📥 Installation

This tool requires Python 3.8+ and the following libraries:

```bash
pip install requests
