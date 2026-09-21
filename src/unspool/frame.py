"""The container-level view of one captured packet."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class Frame:
    """One captured frame, as stored in the file, before any protocol decoding.

    ``number`` is 1-based, matching Wireshark's frame numbers, so frame 17 here
    is frame 17 in Wireshark.
    """

    number: int
    linktype: int
    data: bytes = field(repr=False)
    original_length: int
    #: Nanoseconds since the Unix epoch, or ``None`` when the block carries no
    #: timestamp (pcapng Simple Packet Blocks).
    timestamp_ns: int | None = None
    interface_id: int | None = None
    #: Index of the pcapng section the frame came from (always 0 for pcap).
    section: int = 0
    comments: tuple[str, ...] = ()

    @property
    def captured_length(self) -> int:
        return len(self.data)

    @property
    def truncated(self) -> bool:
        """True when the capture stored fewer bytes than were on the wire (snaplen)."""
        return len(self.data) < self.original_length

    @property
    def timestamp(self) -> float | None:
        """Seconds since the Unix epoch as a float (loses sub-microsecond precision)."""
        return None if self.timestamp_ns is None else self.timestamp_ns / 1e9

    @property
    def datetime(self) -> datetime | None:
        """Timestamp as an aware UTC ``datetime`` (microsecond precision)."""
        if self.timestamp_ns is None:
            return None
        seconds, nanos = divmod(self.timestamp_ns, 1_000_000_000)
        try:
            base = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        return base.replace(microsecond=nanos // 1000)
