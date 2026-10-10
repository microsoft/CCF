# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Capture Python test failures before runners flatten them into exit codes."""

import contextlib
import contextvars
import dataclasses
import html
import inspect
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
__test__ = False
REPORT_DIR_ENV = "CCF_TEST_REPORT_DIR"
MAX_ANNOTATIONS = 10
MAX_SUMMARY_FAILURES = 100
_write_lock = threading.Lock()


@dataclasses.dataclass(frozen=True)
class TestContext:
    ctest: str = ""
    runner: str = ""
    workspace: str = ""
    case: str = ""
    description: str = ""


EMPTY_CONTEXT = TestContext()
CURRENT_TEST = contextvars.ContextVar("ccf_test", default=EMPTY_CONTEXT)


def case_name(func):
    func = inspect.unwrap(func)
    module = func.__module__
    if module == "__main__":
        module = Path(inspect.getfile(func)).stem
    return f"{module}.{func.__qualname__}"


@contextlib.contextmanager
def test_context(context):
    token = CURRENT_TEST.set(context)
    try:
        yield
    finally:
        CURRENT_TEST.reset(token)


@contextlib.contextmanager
def test_case(func, description):
    context = dataclasses.replace(
        CURRENT_TEST.get(), case=case_name(func), description=description
    )
    with test_context(context):
        try:
            yield
        except Exception as exc:
            # Decorators may be nested, or the exception may be caught by a
            # negative test. Attach identity here; only an owner records failure.
            if not hasattr(exc, "_ccf_case"):
                exc._ccf_case = context
            raise


def exception_chain(exc):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)


def repository_path(filename):
    path = Path(filename)
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    if path.is_file() and path.is_relative_to(ROOT):
        return path.relative_to(ROOT).as_posix()
    return ""


def record_failure(exc, *, context=None, case=None, thread=""):
    context = context or CURRENT_TEST.get()
    chain = list(exception_chain(exc))
    if any(getattr(item, "_ccf_reported", False) for item in chain):
        return
    metadata = next(
        (item._ccf_case for item in chain if hasattr(item, "_ccf_case")), context
    )
    path, line = "", 0
    inferred_case = ""
    for item in chain:
        for frame, lineno in traceback.walk_tb(item.__traceback__):
            candidate = repository_path(frame.f_code.co_filename)
            if not candidate or candidate in {
                "tests/infra/runner.py",
                "tests/infra/test_reporting.py",
                "tests/suite/test_requirements.py",
            }:
                continue
            path, line = candidate, lineno
            if frame.f_code.co_name.startswith("test_"):
                inferred_case = f"{Path(candidate).stem}.{frame.f_code.co_name}"

    record = {
        "ctest": os.getenv("CCF_CTEST_NAME") or context.ctest or "Python test",
        "runner": context.runner,
        "case": case_name(case) if case else metadata.case or inferred_case,
        "description": metadata.description,
        "thread": thread,
        "workspace": context.workspace,
        "path": path,
        "line": line,
        "message": "\nCaused by: ".join(
            f"{type(item).__name__}: {item}" for item in chain
        ),
        "traceback": "".join(
            traceback.TracebackException.from_exception(
                exc, capture_locals=False
            ).format()
        ),
    }
    with _write_lock:
        if any(getattr(item, "_ccf_reported", False) for item in chain):
            return
        report_dir = os.getenv(REPORT_DIR_ENV)
        if report_dir:
            # A separate, atomically published file per failure survives other
            # concurrent tests, and already-recorded failures survive a timeout.
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=report_dir,
                    suffix=".tmp",
                    delete=False,
                ) as output:
                    json.dump(record, output)
                Path(output.name).replace(Path(output.name).with_suffix(".json"))
            except OSError as error:
                print(f"Could not write test failure record: {error}", file=sys.stderr)
                exc.add_note(f"Could not write test failure record: {error}")
                return
        else:
            print("CCF test failure: " + json.dumps(record), flush=True)
        exc._ccf_reported = True


def install_exception_handler(args):
    context = TestContext(
        ctest=args.label, workspace=os.path.join(args.workspace, args.label)
    )
    previous = getattr(sys.excepthook, "_ccf_previous", sys.excepthook)

    def handle_exception(exc_type, exc, tb):
        try:
            record_failure(exc, context=context)
        finally:
            previous(exc_type, exc, tb)

    handle_exception._ccf_previous = previous
    sys.excepthook = handle_exception


def escape_command(value, *, property_value=False):
    value = str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


def title(record):
    return " / ".join(
        record[key] for key in ("ctest", "runner", "case") if record.get(key)
    )


def annotation(record):
    properties = [f"title={escape_command(title(record)[:250], property_value=True)}"]
    if record.get("path") and record.get("line"):
        properties.extend(
            (
                f"file={escape_command(record['path'], property_value=True)}",
                f"line={record['line']}",
            )
        )
    details = [record.get("description", ""), record["message"]]
    if record.get("thread"):
        details.append(f"Thread: {record['thread']}")
    if record.get("workspace"):
        details.append(f"Workspace prefix: {record['workspace']}")
    message = "\n".join(detail for detail in details if detail)
    if len(message) > 3000:
        message = message[:3000] + "\n[truncated; see full test output in the job log]"
    return f"::error {','.join(properties)}::{escape_command(message)}"


def doctest_failure(output):
    """Extract doctest's explicit diagnostics, not arbitrary error log lines."""
    output = re.sub(r"\x1b\[[0-9;]*m", "", output)
    if "[doctest]" not in output:
        return {}
    pattern = r"^(.+\.(?:cpp|cc|h)):(\d+): (?:FATAL )?ERROR: (.+)$"
    blocks = [
        block.strip()
        for block in re.split(r"^={5,}\s*$", output, flags=re.MULTILINE)
        if re.search(pattern, block, re.MULTILINE)
    ]
    errors = list(re.finditer(pattern, output, re.MULTILINE))
    if not errors:
        return {}
    first = errors[0]
    filename = first[1]
    filename = filename.removeprefix("CCF/")
    return {
        "case": "; ".join(
            case
            for block in blocks
            for case in re.findall(r"^TEST CASE:\s*(.+)$", block, re.MULTILINE)
        ),
        "path": repository_path(filename),
        "line": int(first[2]),
        "message": "\n\n".join(blocks),
    }


def collect_failures(report_dir, kind, returncode):
    records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(report_dir.glob("*.json"))
    ]
    reported = {record["ctest"] for record in records}
    junit = report_dir / "junit.xml"
    if junit.exists():
        for test in ET.parse(junit).iter("testcase"):
            failures = list(test.findall("failure")) + list(test.findall("error"))
            if kind == "ctest" and test.get("status") == "notrun":
                failures.extend(
                    skipped
                    for skipped in test.findall("skipped")
                    if not skipped.get("message", "").startswith(
                        ("Disabled", "SKIP_RETURN_CODE", "SKIP_REGULAR_EXPRESSION")
                    )
                )
            if not failures:
                continue
            name = test.get("name", "Unnamed test")
            output = test.findtext("system-out", "")
            # Only an ordinary nonzero exit is explained by Python failures.
            # Signals, timeouts and execution failures are additional outcomes.
            ordinary_failure = all(
                failure.get("message", "").lower() == "failed" for failure in failures
            )
            if kind == "ctest" and name in reported and ordinary_failure:
                continue
            messages = [
                failure.get("message") or failure.text or "Test failed"
                for failure in failures
            ]
            record = {
                "ctest": name if kind == "ctest" else "Python SDK",
                "case": (
                    "" if kind == "ctest" else f"{test.get('classname', '')}.{name}"
                ),
                "message": "\n".join(messages),
                "path": repository_path(str(Path.cwd() / test.get("file", ""))),
                "line": int(test.get("line", "-1")) + 1,
            }
            if kind == "ctest":
                details = doctest_failure(output)
                record.update(details)
                record["message"] = "\n".join(
                    [*messages, details.get("message", output[-2400:])]
                )
            records.append(record)
    if returncode and not records:
        records.append(
            {
                "ctest": kind,
                "message": (
                    f"Test command exited with status {returncode} without a failure "
                    "record. Check the job log for setup, collection or process errors."
                ),
            }
        )
    return sorted(records, key=title)


def publish(report_dir, kind, returncode):
    records = collect_failures(report_dir, kind, returncode)
    if os.getenv("GITHUB_ACTIONS") == "true":
        for record in records[:MAX_ANNOTATIONS]:
            print(annotation(record), flush=True)
        summary = os.getenv("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as output:
                output.write(f"\n### {kind} test results: {len(records)} failures\n\n")
                output.write(f"Command exit status: `{returncode}`.\n\n")
                if records:
                    output.write("| Test | Failure | Location |\n|---|---|---|\n")
                    for record in records[:MAX_SUMMARY_FAILURES]:

                        def cell(value):
                            return (
                                html.escape(str(value))
                                .replace("|", "&#124;")
                                .replace("\n", "<br>")
                            )

                        location = record.get("path", "")
                        if location and record.get("line"):
                            location += f":{record['line']}"
                        output.write(
                            f"| {cell(title(record))} | {cell(record['message'][:500])} "
                            f"| {cell(location)} |\n"
                        )
                    output.write(
                        f"\nShowing up to {MAX_ANNOTATIONS} annotations and "
                        f"{MAX_SUMMARY_FAILURES} summary rows per invocation. "
                        "Full test output is in the job log; "
                        "node logs are in the existing log artifacts.\n"
                    )
                if os.getenv("GITHUB_REPOSITORY") and os.getenv("GITHUB_RUN_ID"):
                    url = (
                        f"{os.getenv('GITHUB_SERVER_URL', 'https://github.com')}/"
                        f"{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
                        f"{os.environ['GITHUB_RUN_ID']}"
                    )
                    output.write(f"\n[Workflow logs and artifacts]({url})\n")
    return records


def main():
    kind, *args = sys.argv[1:]
    if kind not in {"ctest", "pytest"}:
        raise ValueError(f"Unknown test reporter: {kind}")
    root = Path("test-results").resolve()
    root.mkdir(exist_ok=True)
    report_dir = Path(tempfile.mkdtemp(prefix=f"{kind}-", dir=root))
    env = dict(os.environ, **{REPORT_DIR_ENV: str(report_dir)})
    command = (
        ["bash", *args]
        if kind == "ctest"
        else [
            sys.executable,
            "-m",
            "pytest",
            *args,
            "-o",
            "junit_family=xunit1",
            f"--junitxml={report_dir / 'junit.xml'}",
        ]
    )
    result = subprocess.run(command, env=env, check=False)
    reporting_failed = False
    try:
        publish(report_dir, kind, result.returncode)
    except (OSError, ValueError, ET.ParseError) as exc:
        reporting_failed = True
        print(f"Test result reporting failed: {exc}", file=sys.stderr)
        if os.getenv("GITHUB_ACTIONS") == "true":
            print(f"::error::Test result reporting failed: {escape_command(exc)}")
    # Do not turn a failing test into success, or hide a reporter failure.
    if result.returncode < 0:
        return 128 - result.returncode
    return result.returncode or int(reporting_failed)


if __name__ == "__main__":
    sys.exit(main())
