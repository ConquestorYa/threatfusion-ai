from collections.abc import Iterable
from dataclasses import dataclass

from .models import IOCRecord, IOCType
from .normalization import normalize_ioc_value


@dataclass
class IOCGroup:
    value: str
    ioc_type: IOCType
    records: list[IOCRecord]

    @property
    def sources(self) -> set[str]:
        return {record.source for record in self.records}

    @property
    def source_count(self) -> int:
        return len(self.sources)


def correlate_iocs(records: Iterable[IOCRecord]) -> list[IOCGroup]:
    groups: dict[tuple[str, IOCType], IOCGroup] = {}

    for record in records:
        normalized_value = normalize_ioc_value(record.value, record.ioc_type)
        key = (normalized_value, record.ioc_type)

        if key not in groups:
            groups[key] = IOCGroup(
                value=normalized_value,
                ioc_type=record.ioc_type,
                records=[],
            )

        groups[key].records.append(record)

    return list(groups.values())