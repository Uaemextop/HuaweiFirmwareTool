"""Main app orchestrator for engine registration and access."""

from __future__ import annotations

from typing import Any, Dict


class AppOrchestratorEngine:
    """Coordinates shared engines and lifecycle hooks."""

    def __init__(self) -> None:
        self._engines: Dict[str, Any] = {}

    def register_engine(self, name: str, engine: Any) -> None:
        self._engines[name] = engine

    def get_engine(self, name: str, default: Any = None) -> Any:
        return self._engines.get(name, default)

    def bootstrap(self) -> None:
        for engine in self._engines.values():
            hook = getattr(engine, "bootstrap", None)
            if callable(hook):
                hook()

    def teardown(self) -> None:
        for engine in self._engines.values():
            hook = getattr(engine, "teardown", None)
            if callable(hook):
                hook()
