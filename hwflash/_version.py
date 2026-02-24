"""Version information for hwflash.

Keeping the version string in a dedicated module avoids circular-import
issues when other modules inside the package need it at import time
(e.g. the splash screen).
"""

__version__ = "1.0.0"
