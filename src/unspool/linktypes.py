"""Link-layer header types (the LINKTYPE_* registry used by pcap and pcapng)."""

from __future__ import annotations

NULL = 0            # BSD loopback, address family in host byte order
ETHERNET = 1
PPP = 9
RAW_BSD = 12        # DLT_RAW on most BSDs; files usually carry 101 instead
RAW_OPENBSD = 14
PPP_HDLC = 50
PPP_ETHER = 51      # PPPoE
RAW = 101           # raw IPv4 or IPv6, version from the first nibble
IEEE802_11 = 105
LOOP = 108          # OpenBSD loopback, address family in network byte order
LINUX_SLL = 113
IEEE802_11_RADIOTAP = 127
IPV4 = 228
IPV6 = 229
LINUX_SLL2 = 276

NAMES = {
    NULL: "BSD loopback",
    ETHERNET: "Ethernet",
    PPP: "PPP",
    RAW_BSD: "Raw IP",
    RAW_OPENBSD: "Raw IP",
    PPP_HDLC: "PPP in HDLC framing",
    PPP_ETHER: "PPPoE",
    RAW: "Raw IP",
    IEEE802_11: "IEEE 802.11",
    LOOP: "OpenBSD loopback",
    LINUX_SLL: "Linux cooked (SLL)",
    IEEE802_11_RADIOTAP: "802.11 + radiotap",
    IPV4: "Raw IPv4",
    IPV6: "Raw IPv6",
    LINUX_SLL2: "Linux cooked v2 (SLL2)",
    6: "Token Ring",
    10: "FDDI",
    104: "Cisco HDLC",
    107: "Frame Relay",
    119: "Prism + 802.11",
    143: "DOCSIS",
    147: "User 0",
    148: "User 1",
    149: "User 2",
    163: "AVS + 802.11",
    165: "SCCP",
    177: "LAPD",
    187: "Bluetooth HCI H4",
    189: "USB (Linux)",
    192: "PPI",
    195: "IEEE 802.15.4",
    201: "Bluetooth HCI H4 + PHDR",
    215: "IEEE 802.15.4 non-ASK PHY",
    220: "USB (Linux, mmapped)",
    227: "SocketCAN",
    230: "IEEE 802.15.4 no-FCS",
    240: "Netlink",
    249: "USBPcap",
    252: "Upper PDU",
    254: "Bluetooth LE LL",
    256: "Bluetooth LE LL + PHDR",
    272: "Nordic BLE",
    279: "Bluetooth BR/EDR baseband",
}

#: Link types the packet decoder knows how to strip.
DECODED = frozenset({
    NULL, ETHERNET, PPP, RAW_BSD, RAW_OPENBSD, PPP_HDLC, RAW, LOOP,
    LINUX_SLL, IPV4, IPV6, LINUX_SLL2,
})


def name(linktype: int) -> str:
    """Human-readable name for a link type, e.g. ``name(1) == "Ethernet"``."""
    return NAMES.get(linktype, f"linktype {linktype}")
