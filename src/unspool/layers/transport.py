"""Transport-layer headers: TCP and UDP."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from ..errors import DecodeError
from .base import Layer, MalformedLayerError

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
_FLAG_NAMES = ((SYN, "SYN"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH"), (ACK, "ACK"),
               (URG, "URG"), (ECE, "ECE"), (CWR, "CWR"))

TCP_OPTION_NAMES = {
    0: "EOL", 1: "NOP", 2: "MSS", 3: "WS", 4: "SACK_PERM", 5: "SACK", 8: "TS",
    19: "MD5", 28: "UTO", 29: "TCP-AO", 30: "MPTCP", 34: "TFO",
}


@dataclass(frozen=True, slots=True)
class TCPOption:
    kind: int
    data: bytes

    @property
    def name(self) -> str:
        return TCP_OPTION_NAMES.get(self.kind, f"opt{self.kind}")

    @property
    def value(self) -> object:
        """Decoded value for the options worth decoding."""
        d = self.data
        if self.kind == 2 and len(d) == 2:
            return int.from_bytes(d, "big")               # MSS
        if self.kind == 3 and len(d) == 1:
            return d[0]                                   # window scale shift
        if self.kind == 8 and len(d) == 8:
            return (int.from_bytes(d[:4], "big"), int.from_bytes(d[4:], "big"))
        if self.kind == 5 and len(d) % 8 == 0:
            return tuple((int.from_bytes(d[i:i + 4], "big"),
                          int.from_bytes(d[i + 4:i + 8], "big")) for i in range(0, len(d), 8))
        return d


@dataclass(slots=True)
class TCP(Layer):
    name: ClassVar[str] = "tcp"
    sport: int
    dport: int
    seq: int
    ack: int
    header_length: int
    flags: int
    window: int
    checksum: int
    urgent: int
    options: tuple[TCPOption, ...] = ()
    payload_length: int = 0
    payload: bytes = field(default=b"", repr=False)

    @property
    def syn(self) -> bool:
        return bool(self.flags & SYN)

    @property
    def fin(self) -> bool:
        return bool(self.flags & FIN)

    @property
    def rst(self) -> bool:
        return bool(self.flags & RST)

    @property
    def has_ack(self) -> bool:
        return bool(self.flags & ACK)

    @property
    def flag_names(self) -> str:
        return ", ".join(name for bit, name in _FLAG_NAMES if self.flags & bit)

    def option(self, name: str) -> object:
        for opt in self.options:
            if opt.name == name:
                return opt.value
        return None

    def summary(self) -> str:
        text = f"{self.sport} → {self.dport} [{self.flag_names}] Seq={self.seq}"
        if self.flags & ACK:
            text += f" Ack={self.ack}"
        return f"{text} Win={self.window} Len={self.payload_length}"


def parse_tcp(data: bytes) -> tuple[TCP, bytes]:
    if len(data) < 20:
        raise DecodeError(f"TCP header needs 20 bytes, have {len(data)}")
    hlen = (data[12] >> 4) * 4
    tcp = TCP(
        sport=(data[0] << 8) | data[1], dport=(data[2] << 8) | data[3],
        seq=int.from_bytes(data[4:8], "big"), ack=int.from_bytes(data[8:12], "big"),
        header_length=hlen, flags=data[13] | ((data[12] & 0x01) << 8),
        window=(data[14] << 8) | data[15], checksum=(data[16] << 8) | data[17],
        urgent=(data[18] << 8) | data[19],
    )
    if hlen < 20:
        raise MalformedLayerError(tcp, f"TCP header length {hlen} is below 20")
    if hlen > len(data):
        raise MalformedLayerError(
            tcp, f"TCP header length {hlen} exceeds the {len(data)} bytes left")
    tcp.options = _tcp_options(data[20:hlen])
    payload = data[hlen:]
    tcp.payload, tcp.payload_length = payload, len(payload)
    return tcp, payload


def _tcp_options(raw: bytes) -> tuple[TCPOption, ...]:
    options = []
    pos = 0
    while pos < len(raw):
        kind = raw[pos]
        if kind == 0:
            break
        if kind == 1:
            pos += 1
            continue
        if pos + 1 >= len(raw):
            break
        length = raw[pos + 1]
        if length < 2 or pos + length > len(raw):
            break  # malformed option list: keep what parsed cleanly
        options.append(TCPOption(kind, raw[pos + 2:pos + length]))
        pos += length
    return tuple(options)


@dataclass(slots=True)
class UDP(Layer):
    name: ClassVar[str] = "udp"
    sport: int
    dport: int
    length: int
    checksum: int
    payload: bytes = field(default=b"", repr=False)

    def summary(self) -> str:
        return f"{self.sport} → {self.dport} Len={len(self.payload)}"


def parse_udp(data: bytes) -> tuple[UDP, bytes]:
    if len(data) < 8:
        raise DecodeError(f"UDP header needs 8 bytes, have {len(data)}")
    udp = UDP((data[0] << 8) | data[1], (data[2] << 8) | data[3],
              (data[4] << 8) | data[5], (data[6] << 8) | data[7])
    if udp.length == 0:
        udp.payload = data[8:]  # IPv6 jumbogram
    elif udp.length < 8:
        raise MalformedLayerError(udp, f"UDP length {udp.length} is below 8")
    else:
        udp.payload = data[8:udp.length]
    return udp, udp.payload
