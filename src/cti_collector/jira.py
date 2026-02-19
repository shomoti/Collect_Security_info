from __future__ import annotations

import json
import logging
import time
from typing import Any
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests
from requests import Response


class JiraClient:
    def __init__(
        self,
        base_url: str,
        email: str,
        token: str,
        project_key: str,
        issue_types: dict[str, str],
        fields: dict[str, dict[str, str]],
        max_retries: int,
        backoff_seconds: int,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        self.issue_types = issue_types
        self.fields = fields
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.auth = (email, token)
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self._field_schema_by_id = self._load_field_schemas()

    def _adf_paragraph(self, text: str) -> dict[str, Any]:
        return {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": text[:3000]}],
                }
            ],
        }

    def _request_with_retry(self, method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.request(method, url, json=payload, timeout=30)
                if resp.status_code in {429, 500, 502, 503, 504}:
                    raise RuntimeError(f"retryable jira status: {resp.status_code} body={self._response_body(resp)}")
                if resp.status_code >= 400:
                    # 4xx is generally non-retryable. Return Jira details to the caller.
                    raise RuntimeError(f"jira status: {resp.status_code} body={self._response_body(resp)}")
                if not resp.text.strip():
                    return {}
                try:
                    return resp.json()
                except ValueError:
                    return {}
            except Exception as exc:
                last_error = exc
                # Do not retry deterministic 4xx validation/auth errors except 429.
                if "jira status: 4" in str(exc):
                    raise RuntimeError(f"Jira request failed: {path}: {exc}") from exc
                sleep_s = self.backoff_seconds * attempt
                self.logger.warning(
                    "jira request retry",
                    extra={"extra": {"attempt": attempt, "path": path, "error": str(exc)}},
                )
                time.sleep(sleep_s)
        raise RuntimeError(f"Jira request failed: {path}: {last_error}")

    def _response_body(self, resp: Response) -> str:
        try:
            return json.dumps(resp.json(), ensure_ascii=False)
        except Exception:
            return resp.text

    def _load_field_schemas(self) -> dict[str, dict[str, Any]]:
        url = f"{self.base_url}/rest/api/3/field"
        try:
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            fields = resp.json()
            out: dict[str, dict[str, Any]] = {}
            if isinstance(fields, list):
                for field in fields:
                    if not isinstance(field, dict):
                        continue
                    field_id = str(field.get("id", ""))
                    schema = field.get("schema", {})
                    if field_id and isinstance(schema, dict):
                        out[field_id] = schema
            return out
        except Exception as exc:
            self.logger.warning(
                "failed to load jira field schemas; fallback to plain values",
                extra={"extra": {"error": str(exc)}},
            )
            return {}

    def create_intel_issue(self, summary: str, description: str, labels: list[str], intel: dict[str, Any]) -> str:
        mapped = self._map_fields("intel", intel)
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "issuetype": {"name": self.issue_types["intel"]},
                "summary": summary[:255],
                "description": self._adf_paragraph(description),
                "labels": labels,
                **mapped,
            }
        }
        data = self._request_with_retry("POST", "/rest/api/3/issue", payload)
        return str(data["key"])

    def create_validation_issue(self, summary: str, description: str, labels: list[str], validation: dict[str, Any]) -> str:
        mapped = self._map_fields("validation", validation)
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "issuetype": {"name": self.issue_types["validation"]},
                "summary": summary[:255],
                "description": self._adf_paragraph(description),
                "labels": labels,
                **mapped,
            }
        }
        data = self._request_with_retry("POST", "/rest/api/3/issue", payload)
        return str(data["key"])

    def add_comment(self, issue_key: str, text: str) -> None:
        payload = {"body": self._adf_paragraph(text)}
        self._request_with_retry("POST", f"/rest/api/3/issue/{issue_key}/comment", payload)

    def get_issue_fields(self, issue_key: str, field_ids: list[str]) -> dict[str, Any]:
        url = f"{self.base_url}/rest/api/3/issue/{issue_key}"
        params = {"fields": ",".join(field_ids)} if field_ids else {}
        resp = self.session.get(url, params=params, timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(f"jira status: {resp.status_code} body={self._response_body(resp)}")
        data = resp.json() if resp.text.strip() else {}
        fields = data.get("fields", {})
        if not isinstance(fields, dict):
            return {}
        return fields

    def update_intel_issue(self, issue_key: str, summary: str, description: str, labels: list[str], intel: dict[str, Any]) -> None:
        mapped = self._map_fields("intel", intel)
        payload = {
            "fields": {
                "summary": summary[:255],
                "description": self._adf_paragraph(description),
                "labels": labels,
                **mapped,
            }
        }
        self._request_with_retry("PUT", f"/rest/api/3/issue/{issue_key}", payload)

    def link_validation_to_intel(self, validation_key: str, intel_key: str) -> None:
        payload = {
            "type": {"name": "Relates"},
            "inwardIssue": {"key": validation_key},
            "outwardIssue": {"key": intel_key},
        }
        self._request_with_retry("POST", "/rest/api/3/issueLink", payload)

    def search_existing_intel_by_source_url(self, issue_type: str, source_url: str, source_field_id: str) -> str | None:
        field_expr = self._to_jql_field_expr(source_field_id)
        escaped_url = source_url.replace('"', "")
        operators = ["=", "~"]
        for operator in operators:
            jql = (
                f'project = "{self.project_key}" '
                f'AND issuetype = "{issue_type}" '
                f'AND {field_expr} {operator} "{escaped_url}"'
            )
            payload = {"jql": jql, "maxResults": 1, "fields": ["key"]}
            try:
                # /search is being removed in Jira Cloud. Use enhanced JQL search endpoint.
                data = self._request_with_retry("POST", "/rest/api/3/search/jql", payload)
            except Exception:
                continue
            issues = data.get("issues", [])
            if issues:
                return str(issues[0]["key"])
        return None

    def search_existing_intel_by_cves(self, issue_type: str, cves: list[str], cve_field_id: str) -> str | None:
        if not cves:
            return None
        field_expr = self._to_jql_field_expr(cve_field_id)
        for cve in cves:
            escaped_cve = cve.replace('"', "")
            operators = ["=", "~"]
            for operator in operators:
                jql = (
                    f'project = "{self.project_key}" '
                    f'AND issuetype = "{issue_type}" '
                    f'AND {field_expr} {operator} "{escaped_cve}"'
                )
                payload = {"jql": jql, "maxResults": 1, "fields": ["key"]}
                try:
                    data = self._request_with_retry("POST", "/rest/api/3/search/jql", payload)
                except Exception:
                    continue
                issues = data.get("issues", [])
                if issues:
                    return str(issues[0]["key"])
        return None

    def _to_jql_field_expr(self, field_id: str) -> str:
        if field_id.startswith("customfield_"):
            suffix = field_id.replace("customfield_", "", 1)
            if suffix.isdigit():
                return f"cf[{suffix}]"
        return f'"{field_id}"'

    def _map_fields(self, kind: str, values: dict[str, Any]) -> dict[str, Any]:
        mapping = self.fields.get(kind, {})
        out: dict[str, Any] = {}
        for logical_name, field_id in mapping.items():
            if logical_name not in values:
                continue
            value = values[logical_name]
            out[field_id] = self._coerce_custom_field_value(field_id, value)
        return out

    def _coerce_custom_field_value(self, field_id: str, value: Any) -> Any:
        schema = self._field_schema_by_id.get(field_id, {})
        schema_type = str(schema.get("type", "")).lower()
        custom_type = str(schema.get("custom", ""))

        # Normalize date/date-time fields to Jira accepted formats.
        if schema_type == "date" or custom_type == "com.atlassian.jira.plugin.system.customfieldtypes:datepicker":
            normalized = self._normalize_datetime_value(value)
            if normalized is not None:
                return normalized.strftime("%Y-%m-%d")
        if schema_type == "datetime" or custom_type == "com.atlassian.jira.plugin.system.customfieldtypes:datetime":
            normalized = self._normalize_datetime_value(value)
            if normalized is not None:
                return normalized.strftime("%Y-%m-%dT%H:%M:%S.000%z")

        # Jira Cloud textarea custom fields require Atlassian Document Format payload.
        if custom_type == "com.atlassian.jira.plugin.system.customfieldtypes:textarea":
            if isinstance(value, (list, dict)):
                text = json.dumps(value, ensure_ascii=False)
            else:
                text = str(value)
            return self._adf_paragraph(text)

        if isinstance(value, (list, dict)):
            return json.dumps(value, ensure_ascii=False)
        return value

    def _normalize_datetime_value(self, value: Any) -> datetime | None:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(value, tz=timezone.utc)
        elif isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            dt = None
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except Exception:
                pass
            if dt is None:
                try:
                    dt = parsedate_to_datetime(s)
                except Exception:
                    dt = None
            if dt is None:
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                    try:
                        dt = datetime.strptime(s, fmt)
                        break
                    except Exception:
                        continue
            if dt is None:
                return None
        else:
            return None

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
