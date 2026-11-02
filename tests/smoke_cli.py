"""Cross-platform Volatility CLI registration smoke check; no dump involved."""

import shutil
import subprocess
from pathlib import Path


PLUGINS = Path(__file__).resolve().parents[1] / "plugins"
NAMES = (
    "tor_session_trace.windows.TorSessionTraceWindows",
    "tor_session_trace.linux.TorSessionTraceLinux",
)
vol = shutil.which("vol")
if not vol:
    raise SystemExit("vol command not found in PATH")

listing = subprocess.run(
    [vol, "-p", str(PLUGINS), "-h"],
    text=True, capture_output=True, check=True,
)
for name in NAMES:
    if name not in listing.stdout:
        raise SystemExit("Plugin was not registered: " + name)
    help_result = subprocess.run(
        [vol, "-p", str(PLUGINS), name, "-h"],
        text=True, capture_output=True,
    )
    if help_result.returncode:
        raise SystemExit(
            f"Plugin help failed for {name} (exit {help_result.returncode})\n"
            f"stdout:\n{help_result.stdout}\nstderr:\n{help_result.stderr}"
        )
    if "--pid PID" not in help_result.stdout:
        raise SystemExit("Required PID option missing: " + name)
    print("OK:", name)
