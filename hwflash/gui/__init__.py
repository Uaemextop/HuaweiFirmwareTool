"""
GUI subpackage for hwflash.

Module layout (single-word filenames):
  colors.py   — shared colour constants and theme palettes
  theme.py    — ThemeMixin: dark/light toggling, ttk styles, animations
  adapters.py — AdaptersMixin: network adapter discovery & selection
  widgets.py  — shared canvas-based widgets (GradientFrame, etc.)
  upgrade.py  — UpgradeTabMixin: main firmware flash tab
  preset.py   — PresetsTabMixin: preset management tab
  verify.py   — VerificationTabMixin: RSA signature verification tab
  encrypt.py  — CryptoTabMixin: config encryption/decryption tab
  term.py     — TerminalTabMixin: Telnet/Serial terminal tab
  dump.py     — DumpTabMixin: MTD firmware dump tab
  settings.py — SettingsTabMixin: advanced settings tab
  info.py     — InfoTabMixin: firmware structure viewer tab
  log.py      — LogTabMixin: audit log tab

Backward-compatible aliases (old ``*_tab.py`` names) still exist as thin
wrappers that re-export from the canonical single-word modules.
"""
