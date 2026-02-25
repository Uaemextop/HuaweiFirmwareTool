"""State synchronization engine for tk variables and lightweight events."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional


class StateSyncEngine:
    """Synchronizes tk variables and dispatches UI events."""

    def __init__(self, state) -> None:
        self.state = state
        self._listeners: Dict[str, List[Callable[[Any], None]]] = defaultdict(list)
        self._guards: Dict[tuple[int, int], bool] = {}

    def bind_bidirectional(self, var_a, var_b, transform_ab=None, transform_ba=None) -> None:
        """Bind two tk variables, propagating updates in both directions."""

        key_ab = (id(var_a), id(var_b))
        key_ba = (id(var_b), id(var_a))

        def _apply(value, transform):
            return transform(value) if transform else value

        def _from_a(*_):
            if self._guards.get(key_ab):
                return
            self._guards[key_ba] = True
            try:
                var_b.set(_apply(var_a.get(), transform_ab))
            finally:
                self._guards[key_ba] = False

        def _from_b(*_):
            if self._guards.get(key_ba):
                return
            self._guards[key_ab] = True
            try:
                var_a.set(_apply(var_b.get(), transform_ba))
            finally:
                self._guards[key_ab] = False

        var_a.trace_add("write", _from_a)
        var_b.trace_add("write", _from_b)

    def publish(self, event: str, payload: Any = None) -> None:
        for callback in list(self._listeners.get(event, [])):
            try:
                callback(payload)
            except Exception:
                pass

    def subscribe(self, event: str, callback: Callable[[Any], None]) -> Callable[[], None]:
        self._listeners[event].append(callback)

        def _unsubscribe() -> None:
            callbacks = self._listeners.get(event, [])
            if callback in callbacks:
                callbacks.remove(callback)

        return _unsubscribe
