"""Widget factory engine for consistent GUI element creation."""

from __future__ import annotations

from dataclasses import dataclass
import tkinter as tk
from tkinter import ttk
from typing import Iterable, Optional, Sequence


@dataclass(frozen=True)
class ActionSpec:
    """Declarative button definition for action rows."""

    text: str
    command: callable
    width: int = 12
    side: str = tk.LEFT
    padx: tuple[int, int] = (0, 4)
    state: str = "normal"


class WidgetFactoryEngine:
    """Creates common tkinter/ttk widget patterns with one call."""

    def section(self, parent, title: str, *, padding: int = 8):
        frame = ttk.LabelFrame(parent, text=title, padding=padding)
        return frame

    def row(self, parent, *, pady: int | tuple[int, int] = 2):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=pady)
        return frame

    def labeled_value(self, parent, *, label: str, variable, label_width: int = 16):
        row = self.row(parent)
        ttk.Label(row, text=label, width=label_width).pack(side=tk.LEFT)
        value = ttk.Label(row, textvariable=variable)
        value.pack(side=tk.LEFT)
        return row, value

    def labeled_entry(
        self,
        parent,
        *,
        label: str,
        variable,
        label_width: int = 18,
        width: int = 16,
        state: str = "normal",
    ):
        row = self.row(parent)
        ttk.Label(row, text=label, width=label_width).pack(side=tk.LEFT)
        entry = ttk.Entry(row, textvariable=variable, width=width, state=state)
        entry.pack(side=tk.LEFT)
        return row, entry

    def labeled_combobox(
        self,
        parent,
        *,
        label: str,
        variable,
        values: Sequence[str],
        label_width: int = 18,
        width: int = 12,
        state: str = "normal",
    ):
        row = self.row(parent)
        ttk.Label(row, text=label, width=label_width).pack(side=tk.LEFT)
        combo = ttk.Combobox(row, textvariable=variable, values=list(values), width=width, state=state)
        combo.pack(side=tk.LEFT)
        return row, combo

    def actions(self, parent, specs: Iterable[ActionSpec], *, pady: tuple[int, int] = (4, 0)):
        row = ttk.Frame(parent)
        row.pack(fill=tk.X, pady=pady)
        buttons = []
        for spec in specs:
            btn = ttk.Button(row, text=spec.text, command=spec.command, width=spec.width, state=spec.state)
            btn.pack(side=spec.side, padx=spec.padx)
            buttons.append(btn)
        return row, buttons

    def table(
        self,
        parent,
        *,
        columns: Sequence[str],
        headings: Sequence[str],
        widths: Optional[Sequence[int]] = None,
        height: int = 6,
    ):
        tree = ttk.Treeview(parent, columns=columns, show="headings", height=height)
        for idx, col in enumerate(columns):
            heading = headings[idx] if idx < len(headings) else col
            tree.heading(col, text=heading)
            if widths and idx < len(widths):
                tree.column(col, width=widths[idx])
        scroll = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        return tree, scroll
