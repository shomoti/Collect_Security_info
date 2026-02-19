import sys
from pathlib import Path
import types

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Keep unit tests runnable even when optional runtime deps are not installed.
if "feedparser" not in sys.modules:
    feedparser_stub = types.ModuleType("feedparser")
    feedparser_stub.parse = lambda *_args, **_kwargs: types.SimpleNamespace(entries=[])
    sys.modules["feedparser"] = feedparser_stub

if "trafilatura" not in sys.modules:
    trafilatura_stub = types.ModuleType("trafilatura")
    trafilatura_stub.extract = lambda *_args, **_kwargs: ""
    sys.modules["trafilatura"] = trafilatura_stub
