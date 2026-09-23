from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class IOCType(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"


@dataclass
class IOCRecord:
    value: str
    ioc_type: IOCType
    source: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    threat_type: str | None = None
    confidence: float | None = None
    tags: list[str] = field(default_factory=list)