"""Aggregate the pipeline's gate results into one fail-closed verdict (TASK-212 PR 4, DEC-112).

Used by the `required-gate` job in .github/workflows/pipeline.yml, which runs `if: always()` and
passes `toJSON(needs)` in NEEDS_JSON plus the event name in EVENT_NAME. It runs from the BASE
commit with no fallback (see `from_base` in the workflow).

Transitional and conservative: every job below is MANDATORY on every PR, docs-only included. No
path-selected skip is allowed yet (`UNSELECTED_SKIP_ALLOWANCES` is empty and a test pins that);
the mechanism exists and is unit-tested so real conditional gates can use it once they exist.

Rejected, each with a fixed message naming only job or output names:
- a mandatory job whose result is failure, cancelled or skipped, or is missing or unrecognised;
- `plan-validation` not `success` on a pull_request (a skip is legitimate only for other events);
- path-selection outputs from `changes` that are missing, not `true`/`false`, or inconsistent
  (`pr-baseline` must always be selected; non-PR events select every gate; `docs-only` must equal
  "only pr-baseline selected");
- any `pr-baseline` child result (exported as workflow outputs) that is not `success`, or missing:
  a green caller alone does not prove its children.
"""

import json
import os
import sys
from collections.abc import Mapping, Sequence
from typing import Any

OK = 0
REJECTED = 1
ERROR = 2

# The exact `needs:` list of the `required-gate` job; a test keeps the workflow and this in sync.
MANDATORY_JOBS = (
    "changes",
    "context",
    "api",
    "db",
    "web",
    "scripts",
    "security-scans",
    "pr-baseline",
)
PR_ONLY_JOBS = ("plan-validation",)
BASELINE_CHILDREN = (
    "dependency-scan-agent",
    "dependency-scan-db",
    "dependency-scan-scripts",
    "dependency-scan-web",
    "sbom",
    "exceptions",
)
GATES = (
    "pr-baseline",
    "data-migration",
    "security-supply-chain",
    "backend-contract",
    "frontend-quality",
    "ai-agent-behavior",
    "staging-promotion",
    "production-release",
)
SELECTION_OUTPUTS = (*GATES, "docs-only")

# job -> gate whose `false` output makes a `skipped` result legitimate. Deliberately EMPTY:
# nothing is path-conditional yet, so every mandatory job must succeed.
UNSELECTED_SKIP_ALLOWANCES: Mapping[str, str] = {}

_KNOWN_RESULTS = {"success", "failure", "cancelled", "skipped"}


def _result(needs: Mapping[str, Any], job: str) -> str | None:
    entry = needs.get(job)
    if not isinstance(entry, Mapping):
        return None
    result = entry.get("result")
    return result if isinstance(result, str) else None


def _outputs(needs: Mapping[str, Any], job: str) -> Mapping[str, Any] | None:
    entry = needs.get(job)
    if not isinstance(entry, Mapping):
        return None
    outputs = entry.get("outputs")
    return outputs if isinstance(outputs, Mapping) else None


def _check_selection(needs: Mapping[str, Any], event: str) -> tuple[list[str], dict[str, str]]:
    outputs = _outputs(needs, "changes")
    if outputs is None:
        return ["changes: path-selection outputs are missing"], {}
    problems: list[str] = []
    values: dict[str, str] = {}
    for name in SELECTION_OUTPUTS:
        value = outputs.get(name)
        if value not in ("true", "false"):
            problems.append(f"changes: path-selection output '{name}' is missing or invalid")
        else:
            values[name] = str(value)
    if problems:
        return problems, {}
    if values["pr-baseline"] != "true":
        problems.append("changes: pr-baseline must be selected on every run")
    only_baseline = all(values[g] == "false" for g in GATES if g != "pr-baseline")
    if (values["docs-only"] == "true") != only_baseline:
        problems.append("changes: docs-only is inconsistent with the selected gates")
    if event != "pull_request" and (
        any(values[g] != "true" for g in GATES) or values["docs-only"] != "false"
    ):
        problems.append("changes: a non-PR event must select every gate")
    return problems, values


def _check_job(
    job: str, result: str | None, selection: Mapping[str, str], allowances: Mapping[str, str]
) -> str | None:
    if result is None:
        return f"{job}: result is missing"
    if result not in _KNOWN_RESULTS:
        return f"{job}: result is not recognised"
    if result == "success":
        return None
    gate = allowances.get(job)
    if result == "skipped" and gate is not None and selection.get(gate) == "false":
        return None  # legitimately unselected by the path mapping
    return f"{job}: {result}" + (" (unexpected skip)" if result == "skipped" else "")


def evaluate(
    needs: Any,
    event: str,
    allowances: Mapping[str, str] = UNSELECTED_SKIP_ALLOWANCES,
) -> list[str]:
    """Reasons the gate must fail; empty when every mandatory control passed."""
    if not isinstance(needs, Mapping) or not needs:
        return ["needs: no job results were provided"]
    problems, selection = _check_selection(needs, event)
    for job in dict.fromkeys((*MANDATORY_JOBS, *allowances)):
        reason = _check_job(job, _result(needs, job), selection, allowances)
        if reason:
            problems.append(reason)
    for job in PR_ONLY_JOBS:
        result = _result(needs, job)
        if event == "pull_request" or result != "skipped":
            reason = _check_job(job, result, selection, {})
            if reason:
                problems.append(reason)
    outputs = _outputs(needs, "pr-baseline")
    if outputs is None:
        problems.append("pr-baseline: child results are missing")
    else:
        for child in BASELINE_CHILDREN:
            value = outputs.get(child)
            if value != "success":
                problems.append(
                    f"pr-baseline/{child}: {value if value in _KNOWN_RESULTS else 'missing'}"
                )
    return problems


def main(argv: Sequence[str]) -> int:
    del argv
    raw, event = os.environ.get("NEEDS_JSON", ""), os.environ.get("EVENT_NAME", "")
    if not raw or not event:
        print("::error::required-gate: NEEDS_JSON and EVENT_NAME are required")
        return ERROR
    try:
        needs = json.loads(raw)
    except ValueError:
        print("::error::required-gate: the job results are not valid JSON")
        return REJECTED
    problems = evaluate(needs, event)
    for problem in problems:
        print(f"::error::required-gate: {problem}")
    if problems:
        return REJECTED
    print(
        f"required-gate: all {len(MANDATORY_JOBS)} mandatory jobs and every baseline child passed"
    )
    return OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
