#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Collect unprivileged diagnostics for intermittent filesystem stalls."""

import argparse
import json
import os
import platform
import signal
import threading
import time
from pathlib import Path
from types import FrameType
from typing import Any, TextIO

PROBE_FILE_NAME = ".ccf-fsync-probe"
PROBE_SIZE = 4096
VMSTAT_FIELDS = {
    "nr_dirty",
    "nr_dirtied",
    "nr_writeback",
    "nr_writeback_temp",
    "nr_written",
    "pgpgout",
}
MEMINFO_FIELDS = {
    "Cached",
    "Dirty",
    "MemAvailable",
    "Writeback",
    "WritebackTmp",
}
CGROUP_IO_FILES = (
    "blkio.io_merged_recursive",
    "blkio.io_queued_recursive",
    "blkio.io_service_bytes_recursive",
    "blkio.io_service_time_recursive",
    "blkio.io_serviced_recursive",
    "blkio.io_wait_time_recursive",
    "blkio.throttle.io_service_bytes",
    "blkio.throttle.io_serviced",
    "blkio.time_recursive",
    "io.pressure",
    "io.stat",
)
VM_WRITEBACK_FIELDS = (
    "dirty_background_bytes",
    "dirty_background_ratio",
    "dirty_bytes",
    "dirty_expire_centisecs",
    "dirty_ratio",
    "dirty_writeback_centisecs",
)


def write_json_line(output: TextIO, value: dict[str, Any]) -> None:
    json.dump(value, output, separators=(",", ":"), sort_keys=True)
    output.write("\n")
    output.flush()


def error_details(path: Path, exc: OSError) -> dict[str, Any]:
    return {
        "errno": exc.errno,
        "message": str(exc),
        "path": str(path),
    }


def read_text(path: Path, errors: list[dict[str, Any]]) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        errors.append(error_details(path, exc))
        return None


def read_selected_values(
    path: Path, selected_fields: set[str], errors: list[dict[str, Any]]
) -> dict[str, str] | None:
    content = read_text(path, errors)
    if content is None:
        return None

    values: dict[str, str] = {}
    for line in content.splitlines():
        parts = line.split(maxsplit=1)
        key = parts[0].rstrip(":")
        if key in selected_fields:
            values[key] = parts[1] if len(parts) > 1 else ""
    return values


def find_io_cgroup(errors: list[dict[str, Any]]) -> Path | None:
    cgroup_description = read_text(Path("/proc/self/cgroup"), errors)
    if cgroup_description is None:
        return None

    unified_path: str | None = None
    for line in cgroup_description.splitlines():
        _, controllers, relative_path = line.split(":", maxsplit=2)
        if "blkio" in controllers.split(","):
            mount = Path("/sys/fs/cgroup/blkio")
            candidate = mount / relative_path.lstrip("/")
            return candidate if candidate.exists() else mount
        if not controllers:
            unified_path = relative_path

    if unified_path is not None:
        mount = Path("/sys/fs/cgroup")
        candidate = mount / unified_path.lstrip("/")
        return candidate if candidate.exists() else mount
    return None


def read_process_io(path: Path, errors: list[dict[str, Any]]) -> dict[str, int] | None:
    content = read_text(path, errors)
    if content is None:
        return None

    values: dict[str, int] = {}
    for line in content.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key] = int(value.strip())
    return values


def read_task_status(path: Path, errors: list[dict[str, Any]]) -> dict[str, str] | None:
    selected = {
        "State",
        "nonvoluntary_ctxt_switches",
        "voluntary_ctxt_switches",
    }
    return read_selected_values(path, selected, errors)


def task_sample(task_path: Path, errors: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schedstat": read_text(task_path / "schedstat", errors),
        "status": read_task_status(task_path / "status", errors),
        "syscall": read_text(task_path / "syscall", errors),
        "tid": int(task_path.name),
        "wchan": read_text(task_path / "wchan", errors),
    }


def process_sample(
    process_path: Path, cwd: str, errors: list[dict[str, Any]]
) -> dict[str, Any]:
    cmdline = read_text(process_path / "cmdline", errors)
    if cmdline is not None:
        cmdline = cmdline.replace("\0", " ").strip()

    tasks: list[dict[str, Any]] = []
    task_root = process_path / "task"
    try:
        task_paths = sorted(
            (entry for entry in task_root.iterdir() if entry.name.isdigit()),
            key=lambda entry: int(entry.name),
        )
    except FileNotFoundError:
        task_paths = []
    except OSError as exc:
        errors.append(error_details(task_root, exc))
        task_paths = []

    for task_path in task_paths:
        try:
            tasks.append(task_sample(task_path, errors))
        except FileNotFoundError:
            continue

    return {
        "cmdline": cmdline,
        "cwd": cwd,
        "io": read_process_io(process_path / "io", errors),
        "pid": int(process_path.name),
        "tasks": tasks,
    }


def collect_workspace_processes(
    process_root: Path, errors: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    processes: list[dict[str, Any]] = []
    process_root_prefix = f"{process_root.resolve()}{os.sep}"

    for process_path in Path("/proc").iterdir():
        if not process_path.name.isdigit():
            continue

        try:
            cwd = os.readlink(process_path / "cwd")
        except (FileNotFoundError, PermissionError):
            continue
        except OSError as exc:
            errors.append(error_details(process_path / "cwd", exc))
            continue

        if cwd != str(process_root) and not cwd.startswith(process_root_prefix):
            continue

        try:
            processes.append(process_sample(process_path, cwd, errors))
        except FileNotFoundError:
            continue

    return processes


def collect_cgroup_io(
    cgroup_path: Path | None, errors: list[dict[str, Any]]
) -> dict[str, str] | None:
    if cgroup_path is None:
        return None

    values: dict[str, str] = {}
    for file_name in CGROUP_IO_FILES:
        path = cgroup_path / file_name
        if not path.exists():
            continue
        content = read_text(path, errors)
        if content is not None:
            values[file_name] = content
    return values


def collect_system_sample(
    scheduled_ns: int,
    process_root: Path,
    cgroup_path: Path | None,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    monotonic_ns = time.monotonic_ns()
    return {
        "cgroup_io": collect_cgroup_io(cgroup_path, errors),
        "cpu_pressure": read_text(Path("/proc/pressure/cpu"), errors),
        "diskstats": read_text(Path("/proc/diskstats"), errors),
        "errors": errors,
        "io_pressure": read_text(Path("/proc/pressure/io"), errors),
        "loadavg": read_text(Path("/proc/loadavg"), errors),
        "loop_delay_ns": max(0, monotonic_ns - scheduled_ns),
        "memory": read_selected_values(Path("/proc/meminfo"), MEMINFO_FIELDS, errors),
        "memory_pressure": read_text(Path("/proc/pressure/memory"), errors),
        "monotonic_ns": monotonic_ns,
        "processes": collect_workspace_processes(process_root, errors),
        "utc_ns": time.time_ns(),
        "vmstat": read_selected_values(Path("/proc/vmstat"), VMSTAT_FIELDS, errors),
    }


def run_system_sampler(
    output_path: Path,
    process_root: Path,
    cgroup_path: Path | None,
    interval_s: float,
    stop_event: threading.Event,
) -> None:
    interval_ns = int(interval_s * 1_000_000_000)
    scheduled_ns = time.monotonic_ns()
    with output_path.open("w", encoding="utf-8", buffering=1) as output:
        while not stop_event.is_set():
            write_json_line(
                output,
                collect_system_sample(scheduled_ns, process_root, cgroup_path),
            )
            scheduled_ns += interval_ns
            remaining_s = (scheduled_ns - time.monotonic_ns()) / 1_000_000_000
            if remaining_s <= 0:
                scheduled_ns = time.monotonic_ns()
                continue
            stop_event.wait(remaining_s)


def run_heartbeat(
    output_path: Path,
    interval_s: float,
    stop_event: threading.Event,
) -> None:
    interval_ns = int(interval_s * 1_000_000_000)
    previous_ns = time.monotonic_ns()
    with output_path.open("w", encoding="utf-8", buffering=1) as output:
        while not stop_event.wait(interval_s):
            monotonic_ns = time.monotonic_ns()
            write_json_line(
                output,
                {
                    "gap_ns": max(0, monotonic_ns - previous_ns - interval_ns),
                    "monotonic_ns": monotonic_ns,
                    "utc_ns": time.time_ns(),
                },
            )
            previous_ns = monotonic_ns


def write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.pwrite(fd, data[offset:], offset)
        if written == 0:
            raise OSError("Zero-length write to fsync probe")
        offset += written


def run_fsync_probe(
    output_path: Path,
    target_dir: Path,
    interval_s: float,
    stop_event: threading.Event,
) -> None:
    probe_path = target_dir / PROBE_FILE_NAME
    fd = os.open(
        probe_path,
        os.O_CLOEXEC | os.O_CREAT | os.O_RDWR | os.O_TRUNC,
        0o600,
    )
    try:
        with output_path.open("w", encoding="utf-8", buffering=1) as output:
            iteration = 0
            while not stop_event.is_set():
                payload = iteration.to_bytes(8, byteorder="little") * (PROBE_SIZE // 8)
                write_start_ns = time.monotonic_ns()
                write_all(fd, payload)
                write_end_ns = time.monotonic_ns()
                marker_ns = time.monotonic_ns()
                write_json_line(
                    output,
                    {
                        "event": "start",
                        "iteration": iteration,
                        "marker_ns": marker_ns,
                        "utc_ns": time.time_ns(),
                        "write_duration_ns": write_end_ns - write_start_ns,
                    },
                )
                fsync_start_ns = time.monotonic_ns()
                os.fsync(fd)
                fsync_end_ns = time.monotonic_ns()
                stat = os.fstat(fd)
                write_json_line(
                    output,
                    {
                        "device": stat.st_dev,
                        "event": "complete",
                        "fsync_duration_ns": fsync_end_ns - fsync_start_ns,
                        "fsync_end_ns": fsync_end_ns,
                        "fsync_start_ns": fsync_start_ns,
                        "inode": stat.st_ino,
                        "iteration": iteration,
                        "marker_to_fsync_ns": fsync_start_ns - marker_ns,
                        "size": stat.st_size,
                        "utc_ns": time.time_ns(),
                    },
                )
                iteration += 1
                stop_event.wait(interval_s)
    finally:
        os.close(fd)


def write_metadata(
    output_path: Path,
    target_dir: Path,
    process_root: Path,
    cgroup_path: Path | None,
    args: argparse.Namespace,
) -> None:
    errors: list[dict[str, Any]] = []
    target_stat = target_dir.stat()
    metadata = {
        "cgroup_io_path": str(cgroup_path) if cgroup_path is not None else None,
        "errors": errors,
        "heartbeat_interval_s": args.heartbeat_interval,
        "mountinfo": read_text(Path("/proc/self/mountinfo"), errors),
        "platform": platform.platform(),
        "probe_interval_s": args.probe_interval,
        "process_root": str(process_root),
        "sample_interval_s": args.sample_interval,
        "started_utc_ns": time.time_ns(),
        "target_device": target_stat.st_dev,
        "target_device_major": os.major(target_stat.st_dev),
        "target_device_minor": os.minor(target_stat.st_dev),
        "target_dir": str(target_dir),
        "uname": list(platform.uname()),
        "vm_writeback": {
            name: read_text(Path("/proc/sys/vm") / name, errors)
            for name in VM_WRITEBACK_FIELDS
        },
    }
    output_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("intervals must be positive")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target-dir",
        required=True,
        type=Path,
        help="Directory on the filesystem being diagnosed",
    )
    parser.add_argument(
        "--process-root",
        required=True,
        type=Path,
        help="Only sample processes whose working directory is below this path",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Directory for diagnostic output, preferably on tmpfs",
    )
    parser.add_argument(
        "--probe-interval",
        default=2.0,
        type=positive_float,
        help="Seconds between 4 KiB write/fsync probes",
    )
    parser.add_argument(
        "--sample-interval",
        default=1.0,
        type=positive_float,
        help="Seconds between procfs samples",
    )
    parser.add_argument(
        "--heartbeat-interval",
        default=0.5,
        type=positive_float,
        help="Seconds between scheduler heartbeat samples",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target_dir = args.target_dir.resolve(strict=True)
    process_root = args.process_root.resolve(strict=False)
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    startup_errors: list[dict[str, Any]] = []
    cgroup_path = find_io_cgroup(startup_errors)
    write_metadata(
        output_dir / "metadata.json",
        target_dir,
        process_root,
        cgroup_path,
        args,
    )
    if startup_errors:
        (output_dir / "startup_errors.json").write_text(
            json.dumps(startup_errors, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    stop_event = threading.Event()
    thread_failure = threading.Event()

    def handle_signal(_signum: int, _frame: FrameType | None) -> None:
        stop_event.set()

    def handle_thread_exception(args: threading.ExceptHookArgs) -> None:
        thread_failure.set()
        stop_event.set()
        with (output_dir / "thread_error.json").open("w", encoding="utf-8") as output:
            json.dump(
                {
                    "exception": repr(args.exc_value),
                    "thread": args.thread.name if args.thread is not None else None,
                    "utc_ns": time.time_ns(),
                },
                output,
                indent=2,
                sort_keys=True,
            )
            output.write("\n")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    threading.excepthook = handle_thread_exception

    threads = [
        threading.Thread(
            name="fsync-probe",
            target=run_fsync_probe,
            args=(
                output_dir / "fsync.jsonl",
                target_dir,
                args.probe_interval,
                stop_event,
            ),
            daemon=True,
        ),
        threading.Thread(
            name="heartbeat",
            target=run_heartbeat,
            args=(
                output_dir / "heartbeat.jsonl",
                args.heartbeat_interval,
                stop_event,
            ),
            daemon=True,
        ),
        threading.Thread(
            name="system-sampler",
            target=run_system_sampler,
            args=(
                output_dir / "system.jsonl",
                process_root,
                cgroup_path,
                args.sample_interval,
                stop_event,
            ),
            daemon=True,
        ),
    ]

    for thread in threads:
        thread.start()

    while not stop_event.wait(1):
        pass

    for thread in threads:
        thread.join(timeout=2)

    probe_path = target_dir / PROBE_FILE_NAME
    if not threads[0].is_alive():
        probe_path.unlink(missing_ok=True)

    return 1 if thread_failure.is_set() else 0


if __name__ == "__main__":
    raise SystemExit(main())
