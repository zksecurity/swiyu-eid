#!/usr/bin/env python3
"""Validate small worker/reviewer result contracts and render review prompts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


CONTRACT_VERSION = "swiyu.worker-result.v1"
ROLES = frozenset({"author", "reviewer"})
AUTHOR_STATUSES = frozenset({"ready_for_review", "blocked", "failed"})
REVIEWER_STATUSES = frozenset({"pass", "changes_requested", "blocked", "failed"})
COMMAND_STATUSES = frozenset({"passed", "failed", "skipped", "not_run"})
ISSUE_SEVERITIES = frozenset({"blocking", "major", "minor", "note"})


class ContractError(ValueError):
    """Raised when a worker result cannot drive the next automated step."""


def _require_dict(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{where} must be an object")
    return value


def _require_nonempty_string(result: dict[str, Any], key: str) -> str:
    value = result.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{key} must be a non-empty string")
    return value


def _require_string_list(result: dict[str, Any], key: str) -> list[str]:
    value = result.get(key)
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ContractError(f"{key} must be a list of non-empty strings")
    return value


def _validate_artifacts(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ContractError("artifacts must be a list")
    artifacts = []
    for index, item in enumerate(value):
        obj = _require_dict(item, f"artifacts[{index}]")
        path = obj.get("path")
        purpose = obj.get("purpose")
        if not isinstance(path, str) or not path.strip():
            raise ContractError(f"artifacts[{index}].path must be a non-empty string")
        if not isinstance(purpose, str) or not purpose.strip():
            raise ContractError(
                f"artifacts[{index}].purpose must be a non-empty string"
            )
        artifacts.append({"path": path, "purpose": purpose})
    return artifacts


def _validate_commands(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ContractError("commands must be a list")
    commands = []
    for index, item in enumerate(value):
        obj = _require_dict(item, f"commands[{index}]")
        command = obj.get("command")
        status = obj.get("status")
        evidence = obj.get("evidence")
        if not isinstance(command, str) or not command.strip():
            raise ContractError(f"commands[{index}].command must be a non-empty string")
        if status not in COMMAND_STATUSES:
            raise ContractError(f"commands[{index}].status is invalid")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ContractError(f"commands[{index}].evidence must be a non-empty string")
        commands.append({"command": command, "status": status, "evidence": evidence})
    return commands


def _validate_issues(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ContractError("issues must be a list")
    issues = []
    for index, item in enumerate(value):
        obj = _require_dict(item, f"issues[{index}]")
        severity = obj.get("severity")
        message = obj.get("message")
        if severity not in ISSUE_SEVERITIES:
            raise ContractError(f"issues[{index}].severity is invalid")
        if not isinstance(message, str) or not message.strip():
            raise ContractError(f"issues[{index}].message must be a non-empty string")
        path = obj.get("path", "")
        if path is not None and not isinstance(path, str):
            raise ContractError(f"issues[{index}].path must be a string when present")
        line = obj.get("line")
        if line is not None and (
            not isinstance(line, int) or isinstance(line, bool) or line < 1
        ):
            raise ContractError(f"issues[{index}].line must be a positive integer")
        issues.append(dict(obj))
    return issues


def _expected_next(role: str, status: str, issues: list[dict[str, Any]]) -> str:
    if role == "author":
        if status == "ready_for_review":
            return "start_reviewer"
        return "master_attention"
    if status == "pass":
        if issues:
            raise ContractError("reviewer pass cannot include issues")
        return "master_accept"
    if status == "changes_requested":
        return "request_repair"
    return "master_attention"


def validate_result(
    result: dict[str, Any], expected_task_id: str | None = None, expected_role: str | None = None
) -> dict[str, Any]:
    """Return a normalized worker result or raise ContractError."""

    result = _require_dict(result, "result")
    if result.get("contract_version") != CONTRACT_VERSION:
        raise ContractError(f"contract_version must be {CONTRACT_VERSION}")

    task_id = _require_nonempty_string(result, "task_id")
    role = _require_nonempty_string(result, "role")
    if role not in ROLES:
        raise ContractError(f"role must be one of {sorted(ROLES)}")
    if expected_task_id is not None and task_id != expected_task_id:
        raise ContractError(f"task_id mismatch: expected {expected_task_id}, got {task_id}")
    if expected_role is not None and role != expected_role:
        raise ContractError(f"role mismatch: expected {expected_role}, got {role}")

    status = _require_nonempty_string(result, "status")
    valid_statuses = AUTHOR_STATUSES if role == "author" else REVIEWER_STATUSES
    if status not in valid_statuses:
        raise ContractError(f"status {status!r} is invalid for role {role}")

    normalized = {
        "contract_version": CONTRACT_VERSION,
        "task_id": task_id,
        "role": role,
        "status": status,
        "summary": _require_nonempty_string(result, "summary"),
        "changed_paths": _require_string_list(result, "changed_paths"),
        "artifacts": _validate_artifacts(result.get("artifacts")),
        "commands": _validate_commands(result.get("commands")),
        "issues": _validate_issues(result.get("issues")),
        "usage": _require_dict(result.get("usage", {}), "usage"),
    }
    if role == "reviewer":
        normalized["reviewed_paths"] = _require_string_list(result, "reviewed_paths")
        if status == "changes_requested" and not normalized["issues"]:
            raise ContractError("changes_requested requires at least one issue")
    expected = _expected_next(role, status, normalized["issues"])
    supplied_next = result.get("next", expected)
    if supplied_next != expected:
        raise ContractError(f"next must be {expected!r} for {role}/{status}")
    normalized["next"] = expected
    return normalized


def validate_review_against_author(
    author_result: dict[str, Any], reviewer_result: dict[str, Any]
) -> dict[str, Any]:
    """Validate a reviewer result against the author result it reviewed."""

    author = validate_result(author_result, expected_role="author")
    reviewer = validate_result(
        reviewer_result, expected_task_id=author["task_id"], expected_role="reviewer"
    )
    if reviewer["status"] == "pass":
        missing = sorted(set(author["changed_paths"]) - set(reviewer["reviewed_paths"]))
        if missing:
            raise ContractError(
                "reviewed_paths must cover every author changed path; missing "
                + ", ".join(missing)
            )
    return reviewer


def next_action(
    author_result: dict[str, Any], reviewer_result: dict[str, Any] | None = None
) -> str:
    """Return the next automation step after one author result and optional review."""

    author = validate_result(author_result, expected_role="author")
    if author["status"] != "ready_for_review":
        return "master_attention"
    if reviewer_result is None:
        return "start_reviewer"
    reviewer = validate_review_against_author(author, reviewer_result)
    if reviewer["status"] == "pass":
        return "master_accept"
    if reviewer["status"] == "changes_requested":
        return "request_repair"
    return "master_attention"


def reviewer_contract_template(task_id: str) -> dict[str, Any]:
    return {
        "contract_version": CONTRACT_VERSION,
        "task_id": task_id,
        "role": "reviewer",
        "status": "pass",
        "summary": "One or two sentences.",
        "changed_paths": [],
        "artifacts": [{"path": "path/to/reviewed-artifact", "purpose": "what you checked"}],
        "commands": [
            {
                "command": "exact command or not_run",
                "status": "passed",
                "evidence": "concise observed result",
            }
        ],
        "issues": [],
        "reviewed_paths": ["every path from the author changed_paths list"],
        "next": "master_accept",
        "usage": {"model": "model-id", "reported_cost": "unknown"},
    }


def author_contract_template(task_id: str) -> dict[str, Any]:
    return {
        "contract_version": CONTRACT_VERSION,
        "task_id": task_id,
        "role": "author",
        "status": "ready_for_review",
        "summary": "One or two sentences.",
        "changed_paths": ["path/to/changed-or-created-file"],
        "artifacts": [{"path": "path/to/artifact", "purpose": "why it matters"}],
        "commands": [
            {
                "command": "exact command or not_run",
                "status": "passed",
                "evidence": "concise observed result",
            }
        ],
        "issues": [],
        "next": "start_reviewer",
        "usage": {"model": "model-id", "reported_cost": "unknown"},
    }


def render_author_prompt(*, task_id: str, original_task: str) -> str:
    template = json.dumps(author_contract_template(task_id), indent=2, sort_keys=True)
    return f"""Complete this bounded worker task.

Original task:
{original_task.strip()}

Rules:
- Stay inside the task scope and paths named in the task.
- Use test-first development when editing source.
- Do not spawn child agents.
- Keep large logs and scratch artifacts under the task's run-owned /private/tmp directory.
- Do not claim a real proof, verifier, benchmark, or artifact hash unless you ran or computed it.
- If blocked, set status to "blocked", next to "master_attention", and name the exact missing condition.

Return only the JSON contract below, with no Markdown fence or extra prose:
{template}
"""


def render_reviewer_prompt(
    *, task_id: str, original_task: str, author_result: dict[str, Any]
) -> str:
    author = validate_result(
        author_result, expected_task_id=task_id, expected_role="author"
    )
    template = json.dumps(reviewer_contract_template(task_id), indent=2, sort_keys=True)
    author_json = json.dumps(author, indent=2, sort_keys=True)
    return f"""Review the completed worker task with a security/protocol review posture.

Original task:
{original_task.strip()}

Author result contract:
```json
{author_json}
```

Review scope:
- Check the changed paths and artifacts named by the author.
- Re-run the listed commands when they are cheap and available.
- Challenge real-proof claims, challenge-binding checks, source/artifact hashes, and any use of stubs.
- Do not do broad unrelated refactors.
- If there are blocking or major issues, set status to "changes_requested" and next to "repair".
- If the result is acceptable, set status to "pass" and next to "master_accept".

Return only the JSON contract below, with no Markdown fence or extra prose:
{template}
"""


def build_pi_command(brief_path: Path, *, model: str, effort: str | None = None) -> list[str]:
    cmd = [
        "pi",
        "--provider",
        "cursor",
        "--model",
        model,
        "--cursor-no-fast",
        "--cursor-runtime",
        "local",
        "--no-session",
        "--mode",
        "json",
        "--no-skills",
        "--no-context-files",
    ]
    if effort:
        cmd.extend(["--thinking", effort])
    cmd.extend(["-p", f"@{brief_path}"])
    return cmd


def _text_from_cursor_message(obj: dict[str, Any]) -> str | None:
    message = obj.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return None
    chunks = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            text = item.get("text")
            if isinstance(text, str):
                chunks.append(text)
    return "\n".join(chunks) if chunks else None


def _json_candidates(raw: str) -> list[str]:
    candidates: list[str] = []
    stripped = raw.strip()
    if stripped:
        candidates.append(stripped)
    for line in raw.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            text = _text_from_cursor_message(obj)
            if text:
                candidates.append(text.strip())
    return candidates


def extract_result_contract(raw: str) -> dict[str, Any]:
    """Extract a worker contract from raw JSON or Cursor JSONL output."""

    errors = []
    for candidate in reversed(_json_candidates(raw)):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as exc:
            errors.append(str(exc))
            continue
        if isinstance(parsed, dict) and parsed.get("contract_version") == CONTRACT_VERSION:
            return parsed
    detail = errors[-1] if errors else "no JSON candidates"
    raise ContractError(f"could not extract {CONTRACT_VERSION}: {detail}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ContractError(f"{path}: invalid JSON: {exc}") from exc


def _cmd_validate(args: argparse.Namespace) -> int:
    result = validate_result(
        load_json(Path(args.path)), expected_task_id=args.task_id, expected_role=args.role
    )
    print(json.dumps({"ok": True, "next": result["next"], "status": result["status"]}))
    return 0


def _cmd_review_prompt(args: argparse.Namespace) -> int:
    prompt = render_reviewer_prompt(
        task_id=args.task_id,
        original_task=Path(args.task).read_text(encoding="utf-8"),
        author_result=load_json(Path(args.author_result)),
    )
    if args.output:
        Path(args.output).write_text(prompt, encoding="utf-8")
    else:
        print(prompt, end="")
    return 0


def _cmd_author_prompt(args: argparse.Namespace) -> int:
    prompt = render_author_prompt(
        task_id=args.task_id,
        original_task=Path(args.task).read_text(encoding="utf-8"),
    )
    if args.output:
        Path(args.output).write_text(prompt, encoding="utf-8")
    else:
        print(prompt, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("path")
    validate.add_argument("--task-id", required=True)
    validate.add_argument("--role", choices=sorted(ROLES), required=True)
    validate.set_defaults(func=_cmd_validate)

    review = sub.add_parser("review-prompt")
    review.add_argument("--task-id", required=True)
    review.add_argument("--task", required=True)
    review.add_argument("--author-result", required=True)
    review.add_argument("--output")
    review.set_defaults(func=_cmd_review_prompt)

    author = sub.add_parser("author-prompt")
    author.add_argument("--task-id", required=True)
    author.add_argument("--task", required=True)
    author.add_argument("--output")
    author.set_defaults(func=_cmd_author_prompt)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ContractError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
