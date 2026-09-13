# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""CI adaptation of the handed-off, untraced /proc measurement harness."""

import csv
import fcntl
import json
import os
import re
import subprocess
import threading
import time
from itertools import pairwise
from pathlib import Path

import psutil

from common import (
    DRIVER,
    MAX_EXTERNAL_CORES,
    MEASURE_SECONDS,
    REVISIONS,
    ROOT,
    SOURCES,
    VENV,
    sha256,
    write_json,
)

_run_lock = (ROOT / ".measurement.lock").open("a")
fcntl.flock(_run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
PACKAGE = "samples/apps/basic/basic"
SERVER_EXECUTABLES = {
    "basic",
    "basic_queue_probe",
    "basic_poll_cached",
    "basic_read_ahead",
}
MARKER_CALLBACK = None


def cpu_seconds(cpu):
    return cpu.user + cpu.system


def tcp_counters():
    lines = Path("/proc/net/snmp").read_text().splitlines()
    for header, values in pairwise(lines):
        if header.startswith("Tcp:") and values.startswith("Tcp:"):
            return dict(zip(header.split()[1:], map(int, values.split()[1:])))
    raise RuntimeError("TCP counters unavailable")


def read_thread(pid, thread):
    directory = Path(f"/proc/{pid}/task/{thread.id}")
    status = dict(
        line.split(":", 1)
        for line in (directory / "status").read_text().splitlines()
        if ":" in line
    )
    io = {
        name: int(value)
        for name, value in (
            line.split(":", 1) for line in (directory / "io").read_text().splitlines()
        )
    }
    return {
        "name": status["Name"].strip(),
        "user_s": thread.user_time,
        "system_s": thread.system_time,
        "voluntary_switches": int(status["voluntary_ctxt_switches"]),
        "involuntary_switches": int(status["nonvoluntary_ctxt_switches"]),
        "io": io,
    }


def collect(root_pid, known):
    all_processes = {
        proc.pid: proc.info
        for proc in psutil.process_iter(["pid", "ppid", "name", "cpu_times"])
        if proc.info["cpu_times"] is not None
    }
    tree = {root_pid}
    previous = set()
    while previous != tree:
        previous = tree.copy()
        tree.update(pid for pid, info in all_processes.items() if info["ppid"] in tree)
    own = {}
    for pid in tree & all_processes.keys():
        info = all_processes[pid]
        try:
            proc = psutil.Process(pid)
            if pid not in known:
                argv = proc.cmdline()
                executable = proc.exe()
                role = "other"
                if Path(executable).name in SERVER_EXECUTABLES:
                    role = "server"
                elif any(Path(arg).name == "locust" for arg in argv):
                    role = "locust"
                known[pid] = {
                    "pid": pid,
                    "ppid": info["ppid"],
                    "name": info["name"],
                    "role": role,
                    "argv": argv,
                    "executable": executable,
                    "affinity": proc.cpu_affinity(),
                    "created_at": proc.create_time(),
                }
                if role == "server":
                    known[pid]["running_binary_sha256"] = sha256(
                        Path(f"/proc/{pid}/exe")
                    )
            data = {
                "name": info["name"],
                "role": known[pid]["role"],
                "user_s": info["cpu_times"].user,
                "system_s": info["cpu_times"].system,
                "threads_count": proc.num_threads(),
                "io": proc.io_counters()._asdict(),
                "threads": {},
            }
            for thread in proc.threads():
                try:
                    data["threads"][thread.id] = read_thread(pid, thread)
                except (FileNotFoundError, ProcessLookupError):
                    # Short-lived startup/shutdown threads may exit between reads.
                    continue
            own[pid] = data
        except (psutil.NoSuchProcess, ProcessLookupError):
            continue
    external = {
        pid: {"name": info["name"], "cpu_s": cpu_seconds(info["cpu_times"])}
        for pid, info in all_processes.items()
        if pid not in tree and pid != os.getpid()
    }
    return {
        "wall_time": time.time(),
        "monotonic_time": time.monotonic(),
        "system": [cpu._asdict() for cpu in psutil.cpu_times(percpu=True)],
        "observer_cpu_s": cpu_seconds(psutil.Process().cpu_times()),
        "loadavg": os.getloadavg(),
        "tcp": tcp_counters(),
        "own": own,
        "external": external,
    }


def rates(before, after, duration):
    result = {key: (after[key] - before[key]) / duration for key in before}
    if any(value < 0 for value in result.values()):
        raise RuntimeError(f"Non-monotonic process counters: {result}")
    return result


def cpu_summary(samples, marker):
    selected = [
        sample
        for sample in samples
        if marker + 2 <= sample["wall_time"] <= marker + MEASURE_SECONDS - 2
    ]
    if len(selected) < 10:
        raise RuntimeError("Insufficient steady-state CPU samples")
    first, last = selected[0], selected[-1]
    duration = last["monotonic_time"] - first["monotonic_time"]
    if not 14 <= duration <= 16.5:
        raise RuntimeError(f"Invalid interior CPU sampling duration: {duration}")
    own = []
    for pid in first["own"].keys() & last["own"].keys():
        before, after = first["own"][pid], last["own"][pid]
        item = {
            "pid": pid,
            "name": after["name"],
            "role": after["role"],
            "user_cores": (after["user_s"] - before["user_s"]) / duration,
            "system_cores": (after["system_s"] - before["system_s"]) / duration,
            "io_per_s": rates(before["io"], after["io"], duration),
            "thread_count": after["threads_count"],
            "threads": [],
        }
        item["cpu_cores"] = item["user_cores"] + item["system_cores"]
        for tid in before["threads"].keys() & after["threads"].keys():
            a, b = before["threads"][tid], after["threads"][tid]
            item["threads"].append(
                {
                    "tid": tid,
                    "name": b["name"],
                    "user_cores": (b["user_s"] - a["user_s"]) / duration,
                    "system_cores": (b["system_s"] - a["system_s"]) / duration,
                    "cpu_cores": (
                        b["user_s"] + b["system_s"] - a["user_s"] - a["system_s"]
                    )
                    / duration,
                    "voluntary_switches_per_s": (
                        b["voluntary_switches"] - a["voluntary_switches"]
                    )
                    / duration,
                    "involuntary_switches_per_s": (
                        b["involuntary_switches"] - a["involuntary_switches"]
                    )
                    / duration,
                    "io_per_s": rates(a["io"], b["io"], duration),
                }
            )
        own.append(item)
    external_totals = {}
    external_peak_cores = 0
    for a, b in pairwise(selected):
        interval_seconds = b["monotonic_time"] - a["monotonic_time"]
        interval_cpu = 0
        for pid, data in b["external"].items():
            delta = data["cpu_s"] - a["external"].get(pid, {"cpu_s": 0})["cpu_s"]
            if delta > 0:
                item = external_totals.setdefault(
                    pid, {"pid": pid, "name": data["name"], "cpu_s": 0}
                )
                item["cpu_s"] += delta
                interval_cpu += delta
        external_peak_cores = max(external_peak_cores, interval_cpu / interval_seconds)
    external = [
        {
            "pid": item["pid"],
            "name": item["name"],
            "cpu_cores": item["cpu_s"] / duration,
        }
        for item in external_totals.values()
    ]
    external.sort(key=lambda process: process["cpu_cores"], reverse=True)
    cpu_fields = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
    host = {
        key: sum(
            b.get(key, 0) - a.get(key, 0)
            for a, b in zip(first["system"], last["system"])
        )
        / duration
        for key in cpu_fields
    }
    busy = sum(host.values()) - host["idle"] - host["iowait"]
    observer = (last["observer_cpu_s"] - first["observer_cpu_s"]) / duration
    visible_external = sum(process["cpu_cores"] for process in external)
    # /proc/stat includes host processes outside the container PID namespace.
    unattributed = max(
        0,
        host["user"]
        + host["nice"]
        + host["system"]
        - sum(process["cpu_cores"] for process in own)
        - visible_external
        - observer,
    )
    return {
        "sample_count": len(selected),
        "window_start": first["wall_time"],
        "window_end": last["wall_time"],
        "duration_s": duration,
        "system_busy_percent": 100 * busy / sum(host.values()),
        "system_busy_cores": busy,
        "host_cpu_cores_by_state": host,
        "observer_cpu_cores": observer,
        "visible_external_cpu_cores": visible_external,
        "unattributed_host_cpu_cores": unattributed,
        "external_cpu_cores": visible_external + unattributed,
        "external_peak_cores": external_peak_cores,
        "external_top": external[:10],
        "host_tcp_per_s": {
            key: (last["tcp"][key] - first["tcp"][key]) / duration
            for key in first["tcp"]
            if key not in ("RtoAlgorithm", "RtoMin", "RtoMax", "MaxConn", "CurrEstab")
        },
        "processes": own,
        "server_count": sum(process["role"] == "server" for process in own),
        "locust_process_count": sum(process["role"] == "locust" for process in own),
    }


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as contents:
        return list(csv.DictReader(contents))


def validate_statistics(rows, markers):
    aggregate_rows = [row for row in rows if row["Name"] == "Aggregated"]
    if len(aggregate_rows) != 1:
        raise RuntimeError("Expected exactly one aggregate Locust row")
    aggregate = aggregate_rows[0]
    count = int(aggregate["Request Count"])
    throughput = float(aggregate["Requests/s"])
    if count <= 0 or throughput <= 0:
        raise RuntimeError("Locust did not record a positive workload")
    if any(int(row["Failure Count"]) != 0 for row in rows):
        raise RuntimeError("Locust recorded request failures")
    duration = count / throughput
    if not 19 <= duration <= 21:
        raise RuntimeError(f"Expected a 20s measured window, observed {duration}s")
    spawned = [event for event in markers if "All users spawned" in event["line"]]
    if len(spawned) != 1:
        raise RuntimeError(f"Expected exactly one completed spawn: {spawned}")
    match = re.search(r"All users spawned: (\{.*\})", spawned[0]["line"])
    if match is None or json.loads(match[1]) != {"Writer": 320}:
        raise RuntimeError(f"Unexpected workload/concurrency: {spawned[0]}")
    marker = spawned[0]["wall_time"]
    if not any(
        "Resetting stats" in event["line"] and abs(event["wall_time"] - marker) < 2
        for event in markers
    ):
        raise RuntimeError("No post-spawn statistics reset was observed")
    return aggregate, duration, marker


def validate_history(rows, marker):
    interior = [
        row
        for row in rows
        if row["Name"] == "Aggregated"
        and marker + 2 <= float(row["Timestamp"]) <= marker + 18
    ]
    if len(interior) < 5 or any(int(row["User Count"]) != 320 for row in interior):
        raise RuntimeError("History does not show 320 users throughout the warm window")
    return {"interior_samples": len(interior), "user_count": 320}


def option(argv, name):
    if argv.count(name) != 1 or argv.index(name) + 1 >= len(argv):
        raise RuntimeError(f"Missing/ambiguous argument {name}: {argv}")
    return argv[argv.index(name) + 1]


def validate_processes(known, result):
    servers = [proc for proc in known.values() if proc["role"] == "server"]
    clients = [proc for proc in known.values() if proc["role"] == "locust"]
    if len(servers) != 1 or len(clients) != 11:
        raise RuntimeError("Expected one Basic process and 11 Locust processes")
    if servers[0]["running_binary_sha256"] != result["binary_sha256"]:
        raise RuntimeError("The running server does not match the selected executable")
    expected = {
        "--users": "320",
        "--spawn-rate": "320",
        "--processes": "10",
        "--measure-time-s": "20",
        "--endpoint": "/records/blocking/{key}",
        "--key-space-size": "1000",
        "--locustfile": str(SOURCES["base"] / "tests/infra/basicperf_locustfile.py"),
    }
    for client in clients:
        argv = client["argv"]
        for name, value in expected.items():
            if option(argv, name) != value:
                raise RuntimeError(f"Client configuration mismatch: {name}")
        if "--reset-stats" not in argv or not option(argv, "--host").startswith(
            "https://"
        ):
            raise RuntimeError("TLS or post-spawn reset was disabled")
        for name in ("--ca", "--cert", "--key"):
            if not Path(option(argv, name)).is_file():
                raise RuntimeError(f"Missing TLS credential file for {name}")


def terminate_owned_processes(process):
    try:
        children = psutil.Process(process.pid).children(recursive=True)
    except psutil.NoSuchProcess:
        children = []
    for child in children:
        try:
            child.terminate()
        except psutil.NoSuchProcess:
            continue
    process.terminate()
    _, remaining = psutil.wait_procs(children, timeout=5)
    for child in remaining:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            continue
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_one(prefix, round_number, version, interval):
    run_id = f"{prefix}-r{round_number}-{version}-{interval}ms"
    run_dir = ROOT / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / "scratch").mkdir()
    build = SOURCES[version] / "build"
    command = [
        str(VENV / "bin" / "python"),
        "-u",
        str(DRIVER),
        "-b",
        str(build),
        "--label",
        run_id,
        "--log-level",
        "info",
        "--worker-threads",
        "2",
    ]
    for name in ("actions", "validate", "resolve", "apply"):
        command += [
            "--constitution",
            str(SOURCES["base"] / "samples/constitutions/default" / f"{name}.js"),
        ]
    command += [
        "--package",
        PACKAGE,
        "--perf-label",
        "Basic Blocking",
        "--snapshot-tx-interval",
        "10000",
        "--users",
        "320",
        "--spawn-rate",
        "320",
        "--locust-processes",
        "10",
        "--measure-time-s",
        str(MEASURE_SECONDS),
        "--sig-ms-intervals",
        str(interval),
        "--tick-ms",
        "1",
        "--workspace",
        str(run_dir / "workspace"),
    ]
    environment = os.environ.copy()
    for key in (
        "CCF_PERF",
        "CCF_PERF_ARGS",
        "CCF_GLIBCXX_DEBUG",
        "CURL_CLIENT",
        "LD_PRELOAD",
    ):
        environment.pop(key, None)
    environment.update(
        PATH=str(VENV / "bin") + os.pathsep + environment["PATH"],
        PYTHONPATH=str(SOURCES["base"] / "tests"),
        PYTHONUNBUFFERED="1",
        PYTHONDONTWRITEBYTECODE="1",
        VENV_DIR=str(VENV),
        TMPDIR=str(run_dir / "scratch"),
        GITHUB_SHA=REVISIONS[version],
    )
    binary = build / PACKAGE
    result = {
        "id": run_id,
        "round": round_number,
        "version": version,
        "revision": REVISIONS[version],
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "interval_ms": interval,
        "command": command,
        "cwd": str(run_dir),
        "start_time": time.time(),
        "accepted": False,
    }
    write_json(run_dir / "command.json", result)
    known, samples, markers = {}, [], []
    print(f"START {run_id}", flush=True)
    try:
        with (run_dir / "stdout.log").open("w", encoding="utf-8") as output, (
            run_dir / "process-samples.jsonl"
        ).open("w", encoding="utf-8") as sample_output:
            process = subprocess.Popen(
                command,
                cwd=run_dir,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            def read_output():
                for line in process.stdout:
                    output.write(line)
                    output.flush()
                    if "All users spawned" in line or "Resetting stats" in line:
                        marker = {"wall_time": time.time(), "line": line.rstrip()}
                        markers.append(marker)
                        if MARKER_CALLBACK is not None:
                            MARKER_CALLBACK(process.pid, marker)

            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            try:
                while process.poll() is None:
                    sample = collect(process.pid, known)
                    samples.append(sample)
                    sample_output.write(json.dumps(sample) + "\n")
                    sample_output.flush()
                    if time.time() - result["start_time"] > 300:
                        raise TimeoutError("Benchmark exceeded 300 seconds")
                    time.sleep(1)
            except BaseException:
                terminate_owned_processes(process)
                raise
            finally:
                reader.join(timeout=10)
                if reader.is_alive():
                    raise RuntimeError("Benchmark output reader did not stop")
            result["returncode"] = process.returncode
        if process.returncode != 0:
            raise RuntimeError(f"{run_id} exited {process.returncode}")
        paths = list((run_dir / "workspace").rglob("locust_stats.csv"))
        if len(paths) != 1:
            raise RuntimeError(f"Expected one Locust CSV, found {paths}")
        aggregate, duration, marker = validate_statistics(read_csv(paths[0]), markers)
        for name in ("locust_failures.csv", "locust_exceptions.csv"):
            path = paths[0].with_name(name)
            if path.exists() and read_csv(path):
                raise RuntimeError(f"Locust recorded failures/exceptions in {name}")
        result["concurrency"] = validate_history(
            read_csv(paths[0].with_name("locust_stats_history.csv")), marker
        )
        result.update(
            requests=int(aggregate["Request Count"]),
            failures=int(aggregate["Failure Count"]),
            throughput=float(aggregate["Requests/s"]),
            median_ms=float(aggregate["Median Response Time"]),
            p99_ms=float(aggregate["99%"]),
            measured_duration_s=duration,
            measurement_marker=marker,
            stats_csv=str(paths[0]),
            cpu=cpu_summary(samples, marker),
        )
        config_paths = {
            path.resolve() for path in (run_dir / "workspace").rglob("*.config.json")
        }
        if len(config_paths) != 1:
            raise RuntimeError(f"Expected one node configuration: {config_paths}")
        config_path = next(iter(config_paths))
        config = json.loads(config_path.read_text())
        expected_config = {
            "worker_threads": 2,
            "tick_interval": "1ms",
            "ledger_signature_delay": f"{interval}ms",
            "consensus_message_timeout": f"{interval}ms",
            "snapshot_tx_count": 10000,
        }
        actual_config = {
            "worker_threads": config["worker_threads"],
            "tick_interval": config["tick_interval"],
            "ledger_signature_delay": config["ledger_signatures"]["delay"],
            "consensus_message_timeout": config["consensus"]["message_timeout"],
            "snapshot_tx_count": config["snapshots"]["tx_count"],
        }
        if actual_config != expected_config:
            raise RuntimeError(f"Unexpected node configuration: {actual_config}")
        result["server_configuration"] = actual_config
        result["config_path"] = str(config_path)
        for proc in result["cpu"]["processes"]:
            if proc["role"] == "server":
                proc["cpu_us_per_tx"] = proc["cpu_cores"] * 1e6 / result["throughput"]
                proc["read_count_per_tx"] = (
                    proc["io_per_s"]["read_count"] / result["throughput"]
                )
                proc["write_count_per_tx"] = (
                    proc["io_per_s"]["write_count"] / result["throughput"]
                )
        if (
            result["cpu"]["server_count"] != 1
            or result["cpu"]["locust_process_count"] != 11
        ):
            raise RuntimeError("Unexpected warm-window process topology")
        for name in ("out", "err"):
            for path in (run_dir / "workspace").rglob(name):
                if path.is_file() and any(
                    marker in path.read_text()
                    for marker in ("[fail ]", "[fatal]", "Atom leak", "atom leakage")
                ):
                    raise RuntimeError(
                        f"Node logged an error, including possible shutdown errors: {path}"
                    )
        validate_processes(known, result)
        if result["cpu"]["external_cpu_cores"] > MAX_EXTERNAL_CORES:
            raise RuntimeError(
                "External CPU contention invalidates this run: "
                f"{result['cpu']['external_cpu_cores']:.3f} cores"
            )
        if sha256(binary) != result["binary_sha256"]:
            raise RuntimeError("Executable changed during measurement")
        result["measurement_validated"] = True
        print(
            f"MEASURED {run_id} {result['throughput']:.1f} tx/s "
            f"failures=0 duration={duration:.3f}s "
            f"external_cores={result['cpu']['external_cpu_cores']:.3f}",
            flush=True,
        )
        return result
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        result["end_time"] = time.time()
        result["markers"] = markers
        write_json(run_dir / "processes.json", known)
        write_json(run_dir / "result.json", result)


def wait_for_quiet(prefix, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    consecutive_quiet = 0
    with (ROOT / "quiet-gate.jsonl").open("a", encoding="utf-8") as output:
        while time.monotonic() < deadline:
            busy = psutil.cpu_percent(interval=5, percpu=True)
            busy_cores = sum(busy) / 100
            output.write(
                json.dumps(
                    {
                        "run": prefix,
                        "wall_time": time.time(),
                        "host_busy_cores": busy_cores,
                    }
                )
                + "\n"
            )
            output.flush()
            consecutive_quiet = (
                consecutive_quiet + 1 if busy_cores < MAX_EXTERNAL_CORES else 0
            )
            if consecutive_quiet >= 2:
                return
    raise TimeoutError(f"No quiet measurement window within {timeout_s}s")
