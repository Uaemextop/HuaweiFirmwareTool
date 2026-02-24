"""Threading utilities for safe UI updates."""

import threading
from typing import Callable, Any, Optional
from functools import wraps


def run_in_thread(daemon: bool = True):
    """
    Decorator to run function in a separate thread.

    Args:
        daemon: Whether thread should be daemon

    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            thread = threading.Thread(target=func, args=args, kwargs=kwargs, daemon=daemon)
            thread.start()
            return thread
        return wrapper
    return decorator


def thread_safe_call(root, callback: Callable, *args, **kwargs) -> None:
    """
    Execute callback in UI thread safely.

    Args:
        root: Tkinter root window
        callback: Function to call
        *args: Positional arguments
        **kwargs: Keyword arguments
    """
    def execute():
        try:
            callback(*args, **kwargs)
        except Exception as e:
            print(f"Error in thread_safe_call: {e}")

    if root:
        root.after(0, execute)
    else:
        execute()


class StoppableThread(threading.Thread):
    """Thread that can be stopped gracefully."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stop_event = threading.Event()

    def stop(self):
        """Signal thread to stop."""
        self._stop_event.set()

    def stopped(self) -> bool:
        """Check if stop was requested."""
        return self._stop_event.is_set()

    def wait(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for stop signal.

        Args:
            timeout: Timeout in seconds

        Returns:
            True if stopped, False if timeout
        """
        return self._stop_event.wait(timeout)
