"""unspool: a pure-Python pcapng parser and protocol decoder.

Read-only by design: it parses capture files and never captures, so it needs
no driver, no administrator rights and no particular operating system.

    import unspool

    with unspool.open("capture.pcapng") as cap:
        for pkt in cap:
            if pkt.dns:
                print(pkt.number, pkt.dns.summary())
"""

from .capture import Capture, Interface, frames, open, packets
from .errors import DecodeError, FormatError, TruncatedError, UnspoolError
from .frame import Frame
from .packet import Decoder, Packet, decode

__version__ = "0.1.0"

__all__ = [
    "Capture", "DecodeError", "Decoder", "FormatError", "Frame", "Interface", "Packet",
    "TruncatedError", "UnspoolError", "__version__", "decode", "frames", "open", "packets",
]
