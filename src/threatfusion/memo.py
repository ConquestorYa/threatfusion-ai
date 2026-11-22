"""A small in-process cache for the shared view helpers (what ``st.cache_data``
and ``st.cache_resource`` provided while Streamlit was the interface).

Results are keyed by the call arguments, kept for ``ttl`` seconds (forever
when None) and at most ``max_entries`` at a time. One lock per function means
a slow computation (for example on-device training) runs once while
concurrent callers wait for its result instead of repeating it. Values are
returned as stored; callers must not mutate them.
"""
from __future__ import annotations

import functools
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def cached(*, max_entries: int, ttl: float | None = None) -> Callable[[Callable[..., T]], Callable[..., T]]:
    def decorate(function: Callable[..., T]) -> Callable[..., T]:
        entries: OrderedDict[tuple, tuple[float, T]] = OrderedDict()
        lock = threading.Lock()

        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            key = (args, tuple(sorted(kwargs.items())))
            with lock:
                now = time.monotonic()
                hit = entries.get(key)
                if hit is not None and (ttl is None or now - hit[0] < ttl):
                    entries.move_to_end(key)
                    return hit[1]
                value = function(*args, **kwargs)
                entries[key] = (now, value)
                entries.move_to_end(key)
                while len(entries) > max_entries:
                    entries.popitem(last=False)
                return value

        def clear() -> None:
            with lock:
                entries.clear()

        wrapper.clear = clear  # type: ignore[attr-defined]
        return wrapper

    return decorate
