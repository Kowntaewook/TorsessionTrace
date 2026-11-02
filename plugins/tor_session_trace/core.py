"""Conservative URL and onion-string extraction from a selected process layer."""

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from volatility3.framework.layers import scanners


MAX_CHARS = 2048
ONION_RE = re.compile(r"(?i)^[a-z2-7]{56}\.onion$")
ASCII_URL = rb"(?i)https?://[^\x00-\x20\x22\x27\x3c\x3e\x5c]{1,2048}"
ASCII_ONION = rb"(?i)[a-z2-7]{56}\.onion"


UTF16_URL_START = rb"(?i)h\x00t\x00t\x00p\x00(?:s\x00)?:\x00/\x00/\x00"
UTF16_CHAR = rb"[^\x00-\x20\x22\x27\x3c\x3e\x5c]\x00"
UTF16_URL = UTF16_URL_START + rb"(?:" + UTF16_CHAR + rb"){1,2048}"
UTF16_ONION = rb"(?i)(?:[a-z2-7]\x00){56}\.\x00o\x00n\x00i\x00o\x00n\x00"
PATTERNS = (
    ("ascii", "url", ASCII_URL),
    ("utf-16le", "url", UTF16_URL),
    ("ascii", "onion_candidate", ASCII_ONION),
    ("utf-16le", "onion_candidate", UTF16_ONION),
)


@dataclass(frozen=True)
class Hit:
    offset: int
    encoding: str
    kind: str
    artifact: str


def normalize(raw: bytes, encoding: str, kind: str) -> Optional[str]:
    try:
        value = raw.decode("utf-16le" if encoding == "utf-16le" else "ascii")
    except UnicodeDecodeError:
        return None
    if kind == "onion_candidate":
        return value.lower() if ONION_RE.fullmatch(value) else None
    value = value.rstrip(".,;:!?)]}")
    if not (value.lower().startswith("http://") or value.lower().startswith("https://")):
        return None
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port  # Reject malformed ports.
    except ValueError:
        return None
    if not hostname or any(c.isspace() for c in hostname):
        return None
    if hostname.lower().endswith(".onion") and not ONION_RE.fullmatch(hostname):
        return None
    return value


def scan_layer(layer, context, sections, progress_callback=None, max_hits=1000):
    """Yield bounded, offset-backed hits. Mapped sections come from Volatility."""
    seen = set()
    count = 0
    for encoding, kind, pattern in PATTERNS:
        scanner = scanners.RegExScanner(pattern)
        for offset in layer.scan(
            context=context,
            scanner=scanner,
            sections=sections,
            progress_callback=progress_callback,
        ):
            if kind == "onion_candidate":
                unit = 2 if encoding == "utf-16le" else 1
                try:
                    prefix = layer.read(max(0, offset - 8 * unit), min(offset, 8 * unit), pad=True)
                except Exception:
                    prefix = b""
                if encoding == "utf-16le":
                    prefix = prefix.decode("utf-16le", errors="ignore").encode("ascii", errors="ignore")
                if prefix.lower().endswith((b"http://", b"https://")):
                    continue
            try:
                raw = layer.read(offset, (MAX_CHARS + 8) * (2 if encoding == "utf-16le" else 1), pad=True)
            except Exception:
                continue
            match = re.match(pattern, raw)
            if not match:
                continue
            artifact = normalize(match.group(0), encoding, kind)
            if artifact is None:
                continue
            key = (offset, encoding, kind, artifact)
            if key in seen:
                continue
            seen.add(key)
            yield Hit(offset, encoding, kind, artifact)
            count += 1
            if count >= max_hits:
                return
