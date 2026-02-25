"""Tests for core.command_engine."""

from hwflash.core.command_engine import CommandResult, SystemCommandEngine


def test_register_and_can_run():
    engine = SystemCommandEngine()
    engine.register("demo.hello", lambda: (True, "ok"))
    assert engine.can_run("demo.hello")


def test_run_tuple_result_conversion():
    engine = SystemCommandEngine()
    engine.register("demo.status", lambda: (True, "Applied"))
    result = engine.run("demo.status")
    assert isinstance(result, CommandResult)
    assert result.ok is True
    assert result.message == "Applied"


def test_run_unknown_command():
    engine = SystemCommandEngine()
    result = engine.run("missing.command")
    assert result.ok is False
    assert "Unknown command" in result.message


def test_ont_quick_commands_has_entries():
    commands = SystemCommandEngine.ont_quick_commands()
    assert commands
    assert any(cmd == "display sysinfo" for _, cmd in commands)
