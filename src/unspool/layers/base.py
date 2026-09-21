"""Shared pieces for protocol layers."""

from __future__ import annotations

import socket
from typing import ClassVar

from ..errors import DecodeError


class Layer:
    """One decoded protocol header within a packet.

    ``name`` is the protocol's short name, chosen to match Wireshark's display
    filter names (``eth``, ``ip``, ``tcp``, ``dns``...) so results can be
    checked against ``tshark`` directly.
    """

    __slots__ = ()
    name: ClassVar[str] = "?"

    def summary(self) -> str:
        return self.name


class MalformedLayerError(DecodeError):
    """Raised by a parser that recognised its header but found it inconsistent.

    Carries the partly decoded layer so the packet still shows that the
    protocol was present, the way Wireshark lists a protocol and then flags
    the frame as malformed.
    """

    def __init__(self, layer: Layer, message: str) -> None:
        super().__init__(message)
        self.layer = layer


def ipv4_text(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def ipv6_text(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, raw)


def mac_text(raw: bytes) -> str:
    return raw.hex(":")
