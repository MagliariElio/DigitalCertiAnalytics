from __future__ import annotations

import logging
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# The OCSP check and the chain validation work once per distinct certificate or domain, while every occurrence used
# to be checked (and logged) on its own. A problem logged while one piece of work runs is therefore handled once per
# occurrence it stands for, so app.log keeps one line per occurrence as before.

# Records at this level and above are repeated; the others (progress, debug details) are handled once
REPEATED_LEVEL = logging.WARNING

# Occurrences the work running in this thread or asyncio task stands for (each task has its own copy)
_COUNT: ContextVar[int] = ContextVar("dca_log_replay_count", default=1)

_NOT_SET = object()


@contextmanager
def repeated(count: int) -> Iterator[None]:
    """Within the block (this thread or task only), records >= WARNING are handled `count` times by the wrapped
    handlers."""
    token = _COUNT.set(max(1, count))
    try:
        yield
    finally:
        _COUNT.reset(token)


class _ReplayingHandle:
    """Replacement of a handler's handle(): the record is handled once per occurrence when it is a problem."""

    def __init__(self, handle):
        self.original = handle

    def __call__(self, record: logging.LogRecord):
        count = _COUNT.get() if record.levelno >= REPEATED_LEVEL else 1
        result = self.original(record)
        for _ in range(count - 1):
            result = self.original(record)
        return result


@contextmanager
def replaying() -> Iterator[None]:
    """Wrap the handlers of the root logger for the block, so that repeated() takes effect."""
    wrapped = []
    for handler in list(logging.getLogger().handlers):
        previous = handler.__dict__.get("handle", _NOT_SET)
        # Nested blocks keep the outer wrapper
        if isinstance(previous, _ReplayingHandle):
            continue
        handler.handle = _ReplayingHandle(handler.handle)
        wrapped.append((handler, previous))
    try:
        yield
    finally:
        for handler, previous in wrapped:
            if previous is _NOT_SET:
                del handler.handle
            else:
                handler.handle = previous
