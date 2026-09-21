"""Loopback OID4VP selected-flow helper (production or fixture mock)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode

from .http_capture import exchange


def create_verification(base: str, body: dict[str, Any]) -> dict[str, Any]:
    payload = json.dumps(body, separators=(",", ":"))
    event = exchange(
        boundary="verifier:management_create",
        method="POST",
        url=base.rstrip("/") + "/management/api/verifications",
        headers=[["Content-Type", "application/json"]],
        body=payload,
    )
    return event


def get_request_object(base: str, request_id: str) -> dict[str, Any]:
    return exchange(
        boundary="verifier:request_object",
        method="GET",
        url=base.rstrip("/") + f"/oid4vp/api/request-object/{request_id}",
        headers=[["Accept", "application/oauth-authz-req+jwt"]],
        body="",
    )


def post_direct_post(
    url: str,
    *,
    state: str,
    vp_token: str,
    extra_fields: dict[str, str] | None = None,
    extra_headers: list[list[str]] | None = None,
) -> dict[str, Any]:
    fields: list[tuple[str, str]] = [("state", state), ("vp_token", vp_token)]
    for key, value in (extra_fields or {}).items():
        fields.append((key, value))
    body = urlencode(fields)
    headers = [["Content-Type", "application/x-www-form-urlencoded"]]
    headers.extend(extra_headers or [])
    return exchange(
        boundary="wallet->verifier:direct_post",
        method="POST",
        url=url,
        headers=headers,
        body=body,
    )


def get_management_result(base: str, request_id: str) -> dict[str, Any]:
    return exchange(
        boundary="verifier:management_result",
        method="GET",
        url=base.rstrip("/") + f"/management/api/verifications/{request_id}",
        headers=[["Accept", "application/json"]],
        body="",
    )
