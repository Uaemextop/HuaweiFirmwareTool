"""Tests for ui.sync_engine."""

import tkinter as tk

from hwflash.ui.sync_engine import StateSyncEngine


def test_bidirectional_var_sync():
    root = tk.Tcl()

    class State:
        pass

    state = State()
    engine = StateSyncEngine(state)
    a = tk.StringVar(master=root, value="A")
    b = tk.StringVar(master=root, value="B")
    engine.bind_bidirectional(a, b)

    a.set("hello")
    assert b.get() == "hello"

    b.set("world")
    assert a.get() == "world"


def test_event_publish_subscribe_and_unsubscribe():
    class State:
        pass

    state = State()
    engine = StateSyncEngine(state)
    received = []
    unsub = engine.subscribe("evt.test", lambda payload: received.append(payload))
    engine.publish("evt.test", {"ok": True})
    unsub()
    engine.publish("evt.test", {"ok": False})

    assert received == [{"ok": True}]
