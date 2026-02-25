"""Core business logic: protocol, firmware, network, crypto, terminal, presets."""

from .command_engine import CommandResult, SystemCommandEngine

__all__ = ["CommandResult", "SystemCommandEngine"]
