from __future__ import annotations

import json
import os
import sys

import requests
import yaml


def main() -> int:
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    jira_cfg = cfg["jira"]
    email = os.getenv(jira_cfg["email_env"])
    token = os.getenv(jira_cfg["token_env"])
    if not email or not token:
        raise RuntimeError("Missing Jira env vars")

    url = jira_cfg["base_url"].rstrip("/") + "/rest/api/3/field"
    r = requests.get(url, auth=(email, token), timeout=30)
    r.raise_for_status()

    fields = r.json()
    custom_fields = [f for f in fields if str(f.get("id", "")).startswith("customfield_")]
    custom_fields.sort(key=lambda x: x.get("name", ""))

    print(json.dumps(custom_fields, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
