"""Data table widget with sorting and filtering."""

import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any, Optional, Callable


class DataTable(ttk.Frame):
    """
    Reusable data table widget with treeview.

    Features:
    - Column sorting
    - Row selection
    - Context menu support
    - Data export
    """

    def __init__(self, parent, columns: List[Dict[str, Any]],
                 on_select: Optional[Callable] = None, height: int = 10):
        """
        Initialize data table.

        Args:
            parent: Parent widget
            columns: List of column definitions with 'id', 'text', 'width'
            on_select: Selection callback
            height: Table height in rows
        """
        super().__init__(parent)

        self.columns = columns
        self.on_select = on_select
        self._data = []

        # Create widgets
        self._create_widgets(height)

    def _create_widgets(self, height: int):
        """Create the UI components."""
        # Create treeview with scrollbars
        scroll_y = ttk.Scrollbar(self, orient=tk.VERTICAL)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        scroll_x = ttk.Scrollbar(self, orient=tk.HORIZONTAL)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        column_ids = [col['id'] for col in self.columns]
        self._tree = ttk.Treeview(
            self,
            columns=column_ids,
            show='headings',
            height=height,
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set
        )
        self._tree.pack(fill=tk.BOTH, expand=True)

        scroll_y.config(command=self._tree.yview)
        scroll_x.config(command=self._tree.xview)

        # Configure columns
        for col in self.columns:
            self._tree.heading(
                col['id'],
                text=col['text'],
                command=lambda c=col['id']: self._sort_by_column(c)
            )
            self._tree.column(col['id'], width=col.get('width', 100))

        # Bind selection
        if self.on_select:
            self._tree.bind('<<TreeviewSelect>>', self._on_selection)

    def _sort_by_column(self, col_id: str):
        """Sort table by column."""
        items = [(self._tree.set(item, col_id), item) for item in self._tree.get_children('')]
        items.sort()

        for index, (_, item) in enumerate(items):
            self._tree.move(item, '', index)

    def _on_selection(self, event):
        """Handle row selection."""
        selection = self.get_selection()
        if self.on_select:
            self.on_select(selection)

    def add_row(self, values: List[Any]):
        """Add a row to the table."""
        self._tree.insert('', tk.END, values=values)
        self._data.append(values)

    def clear(self):
        """Clear all rows."""
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._data.clear()

    def get_selection(self) -> List[Dict[str, Any]]:
        """Get selected rows."""
        selection = []
        for item in self._tree.selection():
            values = self._tree.item(item, 'values')
            row = {col['id']: values[i] for i, col in enumerate(self.columns)}
            selection.append(row)
        return selection

    def get_all_data(self) -> List[List[Any]]:
        """Get all table data."""
        return self._data.copy()
