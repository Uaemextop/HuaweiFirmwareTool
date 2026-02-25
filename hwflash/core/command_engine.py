"""System command engine and command catalog abstractions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, Optional


@dataclass(frozen=True)
class CommandResult:
    """Standard result contract for command execution."""

    ok: bool
    message: str
    payload: Any = None


class SystemCommandEngine:
    """Routes command IDs to safe Python callables.

    This avoids spreading direct command execution logic across tabs.
    """

    def __init__(self) -> None:
        self._registry: Dict[str, Callable[..., Any]] = {}
        self._last: Optional[CommandResult] = None

    def register(self, command_id: str, handler: Callable[..., Any]) -> None:
        self._registry[command_id] = handler

    def register_many(self, mapping: Mapping[str, Callable[..., Any]]) -> None:
        for command_id, handler in mapping.items():
            self.register(command_id, handler)

    def can_run(self, command_id: str) -> bool:
        return command_id in self._registry

    def dry_run(self, command_id: str) -> CommandResult:
        if not self.can_run(command_id):
            result = CommandResult(False, f"Unknown command: {command_id}")
            self._last = result
            return result
        result = CommandResult(True, f"Command available: {command_id}")
        self._last = result
        return result

    def run(self, command_id: str, **kwargs) -> CommandResult:
        handler = self._registry.get(command_id)
        if handler is None:
            result = CommandResult(False, f"Unknown command: {command_id}")
            self._last = result
            return result

        try:
            raw = handler(**kwargs)
            if isinstance(raw, CommandResult):
                self._last = raw
                return raw

            if isinstance(raw, tuple) and len(raw) >= 2 and isinstance(raw[0], bool):
                payload = raw[2] if len(raw) > 2 else None
                result = CommandResult(raw[0], str(raw[1]), payload)
                self._last = result
                return result

            result = CommandResult(True, "OK", raw)
            self._last = result
            return result
        except Exception as exc:
            result = CommandResult(False, str(exc))
            self._last = result
            return result

    def last_result(self) -> Optional[CommandResult]:
        return self._last

    @staticmethod
    def ont_quick_commands() -> list[tuple[str, str]]:
        """Default quick command list for terminal UIs."""
        return [
            ("System Info", "display sysinfo"),
            ("Version", "display version"),
            ("SN", "display sn"),
            ("MAC", "display mac"),
            ("WAN Config", "display wan config"),
            ("Optical", "display optic 0"),
            ("CPU", "display cpu"),
            ("Memory", "display memory"),
            ("Flash", "display flash"),
            ("Partitions", "cat /proc/mtd"),
            ("Processes", "ps"),
            ("Config", "display current-config"),
        ]
