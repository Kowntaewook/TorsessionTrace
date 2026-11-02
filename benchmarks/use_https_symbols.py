"""Use HTTPS for Volatility's Microsoft symbol server on disposable CI runners."""

from pathlib import Path

import volatility3.framework.constants as constants


path = Path(constants.__file__)
source = path.read_text(encoding="utf-8")
old = 'SYMBOL_SERVER_URL = "http://msdl.microsoft.com/download/symbols"'
new = 'SYMBOL_SERVER_URL = "https://msdl.microsoft.com/download/symbols"'
if old not in source:
    raise RuntimeError("Volatility symbol server setting changed; inspect before patching")
path.write_text(source.replace(old, new), encoding="utf-8")
print("Volatility Microsoft symbol server uses HTTPS")
