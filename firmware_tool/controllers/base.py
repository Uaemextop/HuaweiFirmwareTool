"""Base controller class with common functionality."""

import logging
from typing import Any, Callable, Dict, Optional
from threading import Lock


class BaseController:
    """
    Base controller class for all controllers.

    Provides common functionality:
    - Event notification system
    - Thread-safe state management
    - Error handling
    - Logging
    """

    def __init__(self):
        """Initialize base controller."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self._callbacks: Dict[str, list] = {}
        self._state_lock = Lock()
        self._state: Dict[str, Any] = {}

    def register_callback(self, event: str, callback: Callable):
        """
        Register callback for event.

        Args:
            event: Event name
            callback: Function to call when event occurs
        """
        if event not in self._callbacks:
            self._callbacks[event] = []
        self._callbacks[event].append(callback)

    def unregister_callback(self, event: str, callback: Callable):
        """
        Unregister callback for event.

        Args:
            event: Event name
            callback: Function to remove
        """
        if event in self._callbacks:
            try:
                self._callbacks[event].remove(callback)
            except ValueError:
                pass

    def emit_event(self, event: str, *args, **kwargs):
        """
        Emit event to all registered callbacks.

        Args:
            event: Event name
            *args: Positional arguments for callbacks
            **kwargs: Keyword arguments for callbacks
        """
        if event in self._callbacks:
            for callback in self._callbacks[event]:
                try:
                    callback(*args, **kwargs)
                except Exception as e:
                    self.logger.error(f"Error in callback for event '{event}': {e}")

    def get_state(self, key: str, default: Any = None) -> Any:
        """
        Get state value thread-safely.

        Args:
            key: State key
            default: Default value if key not found

        Returns:
            State value or default
        """
        with self._state_lock:
            return self._state.get(key, default)

    def set_state(self, key: str, value: Any):
        """
        Set state value thread-safely.

        Args:
            key: State key
            value: Value to set
        """
        with self._state_lock:
            self._state[key] = value

    def update_state(self, updates: Dict[str, Any]):
        """
        Update multiple state values at once.

        Args:
            updates: Dictionary of state updates
        """
        with self._state_lock:
            self._state.update(updates)

    def handle_error(self, error: Exception, context: str = ""):
        """
        Handle error with logging.

        Args:
            error: Exception that occurred
            context: Context description
        """
        msg = f"{context}: {error}" if context else str(error)
        self.logger.error(msg, exc_info=True)
        self.emit_event('error', error, context)
