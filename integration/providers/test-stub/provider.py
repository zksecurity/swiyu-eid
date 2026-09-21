#!/usr/bin/env python3
"""Test-only reference provider — integration scaffolding, not real ZK."""
import base64
import json
import sys
import uuid
from datetime import date

PROTOCOL = "swiyu.provider.v1"
PROFILE = "swiyu-test-age18-v0"
HANDLES: dict[str, dict] = {}


def reply(req_id: str, status: str, result=None, error=None) -> None:
    msg = {"protocol": PROTOCOL, "id": req_id, "status": status}
    if status == "ok":
        msg["result"] = result or {}
    else:
        msg["error"] = error or {"code": status, "message": status}
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def parse_credential(data: str) -> dict:
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        try:
            return json.loads(base64.urlsafe_b64decode(data + "==").decode())
        except Exception:
            raise ValueError("unparseable credential")


def is_adult(birthdate: str, cutoff: str) -> bool:
    b = date.fromisoformat(birthdate)
    c = date.fromisoformat(cutoff)
    age_years = c.year - b.year - ((c.month, c.day) < (b.month, b.day))
    return age_years >= 18


def handle_initialize(req_id: str, _payload: dict) -> None:
    reply(req_id, "ok", {"profiles": [PROFILE], "operations": [
        "initialize", "prepare", "present", "verify", "cleanup"
    ]})


def handle_prepare(req_id: str, payload: dict) -> None:
    profile = payload.get("profile")
    if profile != PROFILE:
        reply(req_id, "unsupported", error={
            "code": "unsupported_profile",
            "message": f"profile not supported: {profile}",
        })
        return
    cred = payload.get("credential", {})
    if cred.get("format") != "dc+sd-jwt":
        reply(req_id, "error", error={"code": "bad_credential", "message": "format"})
        return
    try:
        parsed = parse_credential(cred.get("data", ""))
    except ValueError as exc:
        reply(req_id, "error", error={"code": "bad_credential", "message": str(exc)})
        return
    handle = str(uuid.uuid4())
    HANDLES[handle] = {"credential": parsed, "profile": profile}
    reply(req_id, "ok", {"handle": handle})


def handle_present(req_id: str, payload: dict) -> None:
    profile = payload.get("profile")
    if profile != PROFILE:
        reply(req_id, "unsupported", error={"code": "unsupported_profile", "message": profile})
        return
    handle = payload.get("handle")
    state = HANDLES.get(handle)
    if not state:
        reply(req_id, "error", error={"code": "bad_handle", "message": "unknown handle"})
        return
    ctx = payload.get("request_context", {})
    cred = state["credential"]
    pres = {
        "profile": profile,
        "nonce": ctx.get("nonce"),
        "audience": ctx.get("audience"),
        "birthdate": cred.get("birthdate"),
        "holder": cred.get("holder"),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(pres, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    reply(req_id, "ok", {
        "presentation": encoded,
        "public_outputs": {"adult_claim": None},
    })


def handle_verify(req_id: str, payload: dict) -> None:
    profile = payload.get("profile")
    if profile != PROFILE:
        reply(req_id, "unsupported", error={"code": "unsupported_profile", "message": profile})
        return
    try:
        raw = base64.urlsafe_b64decode(payload.get("presentation", "") + "==")
        pres = json.loads(raw)
    except Exception:
        reply(req_id, "error", error={"code": "bad_presentation", "message": "decode"})
        return
    ctx = payload.get("request_context", {})
    inputs = payload.get("inputs", {})
    cutoff = inputs.get("cutoff_date", "2024-01-01")
    ok = (
        pres.get("nonce") == ctx.get("nonce")
        and pres.get("audience") == ctx.get("audience")
        and pres.get("profile") == profile
        and is_adult(pres.get("birthdate", "2015-01-01"), cutoff)
    )
    reply(req_id, "ok", {
        "verified": ok,
        "reason": None if ok else "binding_or_predicate_failed",
    })


def handle_cleanup(req_id: str, _payload: dict) -> None:
    HANDLES.clear()
    reply(req_id, "ok", {})


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        if req.get("protocol") != PROTOCOL:
            continue
        op = req.get("operation")
        payload = req.get("payload", {})
        rid = req.get("id", "")
        handlers = {
            "initialize": handle_initialize,
            "prepare": handle_prepare,
            "present": handle_present,
            "verify": handle_verify,
            "cleanup": handle_cleanup,
        }
        fn = handlers.get(op)
        if fn is None:
            reply(rid, "unsupported", error={"code": "unknown_operation", "message": op})
        else:
            fn(rid, payload)


if __name__ == "__main__":
    main()
