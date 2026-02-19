from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cti_collector.config import load_allowed_tags, load_app_config
from cti_collector.logging_utils import setup_logging
from cti_collector.pipeline import run_daily


def main() -> int:
    parser = argparse.ArgumentParser(description="Run daily CTI collection pipeline")
    parser.add_argument("--config", default="config.yaml", help="Path to app config")
    parser.add_argument("--tags", default="tag_dictionary.yaml", help="Path to allowed tags dictionary")
    parser.add_argument("--prompt", default="prompts/system_prompt.txt", help="Path to LLM system prompt")
    parser.add_argument("--disable-jql-fallback", action="store_true", help="Disable Jira JQL duplicate check")
    args = parser.parse_args()

    if not Path(args.config).exists():
        raise FileNotFoundError(f"Config not found: {args.config}. Copy config.example.yaml to config.yaml")

    config = load_app_config(args.config)
    allowed_tags = load_allowed_tags(args.tags)
    setup_logging(config.runtime.log_level)

    run_daily(
        config=config,
        allowed_tags=allowed_tags,
        prompt_path=args.prompt,
        enable_jql_fallback=not args.disable_jql_fallback,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
