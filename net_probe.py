#!/usr/bin/env python3
"""
Network probe: discover live hosts on a range, then scan selected TCP ports.

Requires: system `nmap` on PATH, Python package `python-nmap` (`pip install python-nmap`).

Use only on networks you own or are authorized to test.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

import nmap

# Default TCP ports (common services + DB + LAN)
DEFAULT_PORTS: List[int] = [
    21,  # FTP
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS
    80,  # HTTP
    135,  # MS RPC
    139,  # NetBIOS
    161,  # SNMP
    443,  # HTTPS
    445,  # SMB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    8000,  # HTTP alt
    8009,  # AJP
    8080,  # HTTP alt
    8081,  # HTTP alt
]

DEFAULT_PORT_ARG = ",".join(map(str, DEFAULT_PORTS))

_NmapError = getattr(nmap, "PortScannerError", Exception)


def discover_hosts(
    nm: nmap.PortScanner, network_range: str, timing: int
) -> Tuple[List[str], Dict[str, Dict[str, str]]]:
    """
    Phase 1: ping scan only (-sn). Returns live IPs and per-host discovery metadata.
    """
    nm.scan(hosts=network_range, arguments=f"-sn -T{timing}")
    live: List[str] = []
    meta: Dict[str, Dict[str, str]] = {}
    for host in nm.all_hosts():
        if nm[host].state() != "up":
            continue
        live.append(host)
        meta[host] = {
            "hostname": nm[host].hostname() or "",
            "mac_address": nm[host].get("addresses", {}).get("mac", "N/A"),
        }
    return live, meta


def collect_open_tcp_ports(nm: nmap.PortScanner, host: str) -> List[int]:
    open_ports: List[int] = []
    for port_str, pdata in nm[host].get("tcp", {}).items():
        if pdata.get("state") == "open":
            try:
                open_ports.append(int(port_str))
            except ValueError:
                pass
    open_ports.sort()
    return open_ports


def port_scan_hosts(
    nm: nmap.PortScanner,
    live_hosts: List[str],
    port_arg: str,
    timing: int,
) -> Dict[str, List[int]]:
    """
    Phase 2: TCP port scan on known-live hosts (-Pn skips redundant discovery).
    """
    if not live_hosts:
        return {}
    hosts_str = " ".join(live_hosts)
    nm.scan(hosts=hosts_str, arguments=f"-p {port_arg} -Pn -T{timing}")
    result: Dict[str, List[int]] = {}
    for host in live_hosts:
        if host not in nm.all_hosts():
            result[host] = []
            continue
        result[host] = collect_open_tcp_ports(nm, host)
    return result


def build_report(
    live_hosts: List[str],
    discovery_meta: Dict[str, Dict[str, str]],
    open_by_host: Dict[str, List[int]],
) -> List[Dict[str, Any]]:
    report: List[Dict[str, Any]] = []
    for host in live_hosts:
        meta = discovery_meta.get(host, {})
        report.append(
            {
                "ip": host,
                "hostname": meta.get("hostname") or "",
                "mac_address": meta.get("mac_address", "N/A"),
                "state": "up",
                "open_ports": open_by_host.get(host, []),
            }
        )
    return report


def scan_network(
    network_range: str,
    port_arg: str,
    timing: int,
    *,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    nm = nmap.PortScanner()
    if verbose:
        print("Phase 1: host discovery (ping scan)...", file=sys.stderr)
    live_hosts, discovery_meta = discover_hosts(nm, network_range, timing)
    if verbose:
        print(f"Found {len(live_hosts)} live host(s).", file=sys.stderr)
    if not live_hosts:
        return []
    if verbose:
        print("Phase 2: TCP port scan on live hosts...", file=sys.stderr)
    open_by_host = port_scan_hosts(nm, live_hosts, port_arg, timing)
    return build_report(live_hosts, discovery_meta, open_by_host)


def print_report_text(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print("No reachable hosts found.")
        return
    print("Reachable hosts:")
    for host in rows:
        print(f"IP: {host['ip']}")
        hn = host["hostname"]
        print(f"Hostname: {hn if hn else 'N/A'}")
        print(f"MAC Address: {host['mac_address']}")
        print(f"State: {host['state']}")
        ports = host["open_ports"]
        if ports:
            print(f"Open ports: {', '.join(map(str, ports))}")
        else:
            print("Open ports: none")
hosts.",
    )
    p.add_argument(
        "network",
        help="Target (e.g. 192.168.1.0/24, 10.0.0.5)",
    )
    p.add_argument(
        "-p",
        "--ports",
        default=DEFAULT_PORT_ARG,
        metavar="SPEC",
        help=(
            "Port list or range for nmap -p (default: built-in common list). "
            "Examples: 22,80,443 or 1-1024"
        ),
    )
    p.add_argument(
        "-T",
        "--timing",
        type=int,
        choices=range(0, 6),
        default=3,
        metavar="N",
        help="Nmap timing template -T0..-T5 (default: 3)",
    )
    p.add_argument(
        "-f",
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write output to FILE instead of stdout",
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress messages on stderr",
    )
    return p.parse_args(argv)


def write_text_report(path: str, rows: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        if not rows:
            f.write("No reachable hosts found.\n")
            return
        f.write("Reachable hosts:\n")
        for host in rows:
            f.write(f"IP: {host['ip']}\n")
            hn = host["hostname"]
            f.write(f"Hostname: {hn if hn else 'N/A'}\n")
            f.write(f"MAC Address: {host['mac_address']}\n")
            f.write(f"State: {host['state']}\n")
            ports = host["open_ports"]
            if ports:
                f.write(f"Open ports: {', '.join(map(str, ports))}\n")
            else:
                f.write("Open ports: none\n")
            f.write("-" * 40 + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        rows = scan_network(
            args.network,
            args.ports,
            args.timing,
            verbose=not args.quiet,
        )

        if args.format == "json":
            out = json.dumps(rows, indent=2) + "\n"
        else:
            out = ""

        if args.output:
            if args.format == "json":
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(out)
            else:
                write_text_report(args.output, rows)
            if not args.quiet:
                print(f"Wrote output to {args.output}", file=sys.stderr)
        else:
            if args.format == "json":
                sys.stdout.write(out)
            else:
                print_report_text(rows)

    except _NmapError as e:
        print(f"nmap error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
