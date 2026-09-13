# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Run the fixed, interleaved matrix in one serialized controller."""

import json
import math
import os
import queue
import signal
import statistics
import sys
import time
from pathlib import Path

from common import (
    DRIVER,
    HERE,
    PR_STAGES,
    ROOT,
    SHARED_STAGES,
    SOURCES,
    VARIANTS,
    VENV,
    assert_clean,
    binary_path,
    client_fingerprint,
    measurement_plan,
    sha256,
    write_json,
)


def quantile_upper(histogram, fraction):
    target = histogram["count"] * fraction
    accumulated = 0
    for index, count in enumerate(histogram["bins"]):
        accumulated += count
        if accumulated >= target:
            return min((1 << index) - 1, histogram["max_ns"]) / 1e6
    raise RuntimeError("Histogram bins do not cover the reported count")


def stage_summary(probe, version):
    if probe["errors"] != 0 or set(probe["stages"]) != SHARED_STAGES | PR_STAGES:
        raise RuntimeError("Probe errors or missing/unexpected stages")
    summary = {}
    for name, histogram in probe["stages"].items():
        count = histogram["count"]
        bins = histogram["bins"]
        if len(bins) != 64 or sum(bins) != count or any(value < 0 for value in bins):
            raise RuntimeError(f"Invalid histogram bins: {name}")
        if count == 0:
            if version == "base" and name in PR_STAGES:
                continue
            raise RuntimeError(f"Stage was not exercised: {name}")
        if (
            not 0
            <= histogram["max_ns"]
            <= histogram["total_ns"]
            <= (count * histogram["max_ns"])
        ):
            raise RuntimeError(f"Invalid histogram counters: {name}")
        summary[name] = {
            "count": count,
            "mean_ms": histogram["total_ns"] / count / 1e6,
            "p50_upper_ms": quantile_upper(histogram, 0.5),
            "p99_upper_ms": quantile_upper(histogram, 0.99),
            "max_ms": histogram["max_ns"] / 1e6,
        }
    return summary


class QueueGate:
    def __init__(self, collect):
        self.original_collect = collect
        self.markers = queue.SimpleQueue()
        self.state = {}

    def marker_callback(self, root_pid, marker):
        if "All users spawned" in marker["line"]:
            self.markers.put((root_pid, marker["wall_time"]))

    def collect(self, root_pid, known):
        sample = self.original_collect(root_pid, known)
        while not self.markers.empty():
            pid, marker = self.markers.get_nowait()
            if pid in self.state:
                raise RuntimeError("Duplicate queue-probe spawn marker")
            self.state[pid] = {
                "marker": marker,
                "on": None,
                "off": None,
                "pidfd": None,
            }
        state = self.state.get(root_pid)
        if state is None:
            return sample
        now = time.time()
        if state["on"] is None and now >= state["marker"] + 2:
            servers = [
                pid for pid, proc in sample["own"].items() if proc["role"] == "server"
            ]
            if len(servers) != 1:
                raise RuntimeError(f"Cannot safely identify the probe node: {servers}")
            state["server_pid"] = servers[0]
            state["pidfd"] = os.pidfd_open(servers[0])
            signal.pidfd_send_signal(state["pidfd"], signal.SIGRTMIN + 6)
            state["on"] = now
        if state["off"] is None and now >= state["marker"] + 18:
            if state["pidfd"] is None:
                raise RuntimeError("Queue probe was never enabled")
            signal.pidfd_send_signal(state["pidfd"], signal.SIGRTMIN + 7)
            state["off"] = now
            os.close(state["pidfd"])
            state["pidfd"] = None
        return sample

    def finish(self, result):
        if len(self.state) != 1:
            raise RuntimeError("Expected one probe gate")
        state = next(iter(self.state.values()))
        if state["on"] is None or state["off"] is None:
            raise RuntimeError(f"Incomplete warm-window gate: {state}")
        if not (
            state["marker"] + 2 <= state["on"] <= state["marker"] + 3.5
            and state["marker"] + 18 <= state["off"] < state["marker"] + 20
            and 14 <= state["off"] - state["on"] <= 18
        ):
            raise RuntimeError(f"Probe gate escaped its interior window: {state}")
        servers = [
            proc["pid"]
            for proc in result["cpu"]["processes"]
            if proc["role"] == "server"
        ]
        if servers != [state["server_pid"]]:
            raise RuntimeError("Queue probe and CPU counters describe different nodes")
        path = ROOT / "probes" / f"{result['id']}.{state['server_pid']}.json"
        probe = json.loads(path.read_text())
        result.update(
            queue_probe=probe,
            probe_gate=state,
            stage_summary=stage_summary(probe, result["version"]),
            instrumented_timing=True,
        )

    def close(self):
        for state in self.state.values():
            if state["pidfd"] is not None:
                os.close(state["pidfd"])
                state["pidfd"] = None


def paired_summary(results):
    summaries = []
    for category, interval, baseline, comparison, required_pairs in (
        ("pristine", 2, "base", "pr", 3),
        ("pristine", 20, "base", "pr", 2),
        ("cache", 2, "pr", "pr_cached", 2),
        ("read_ahead", 2, "pr", "pr_read_ahead", 2),
    ):
        selected = [
            result
            for result in results
            if result["category"] == category
            and result["interval_ms"] == interval
            and result["accepted"]
        ]
        pairs = []
        for number in sorted({result["pair"] for result in selected}):
            pair = {
                result["variant"]: result
                for result in selected
                if result["pair"] == number
            }
            if set(pair) == {baseline, comparison}:
                pairs.append(
                    {
                        "pair": number,
                        "baseline_run": pair[baseline]["id"],
                        "comparison_run": pair[comparison]["id"],
                        "baseline_tx_s": pair[baseline]["throughput"],
                        "comparison_tx_s": pair[comparison]["throughput"],
                        "ratio": pair[comparison]["throughput"]
                        / pair[baseline]["throughput"],
                    }
                )
        summaries.append(
            {
                "category": category,
                "interval_ms": interval,
                "baseline": baseline,
                "comparison": comparison,
                "required_pairs": required_pairs,
                "complete": len(pairs) == required_pairs,
                "pairs": pairs,
                "geometric_ratio": (
                    math.exp(statistics.mean(math.log(pair["ratio"]) for pair in pairs))
                    if pairs
                    else None
                ),
            }
        )
    return summaries


def main():
    state = {
        "status": "preparing",
        "started_at": time.time(),
        "plan": measurement_plan(),
        "completed_runs": 0,
    }
    write_json(ROOT / "measurement-state.json", state)
    results = []
    try:
        build_state = json.loads((ROOT / "build-state.json").read_text())
        manifest = json.loads((ROOT / "build-manifest.json").read_text())
        if build_state["status"] != "complete" or set(manifest["variants"]) != set(
            VARIANTS
        ):
            raise RuntimeError("All six builds must finish before measuring")
        if Path(sys.prefix).resolve() != VENV.resolve():
            raise RuntimeError("Use the shared baseline venv to run this controller")
        for source in SOURCES.values():
            assert_clean(source)
        for variant in VARIANTS:
            if (
                sha256(binary_path(variant))
                != manifest["variants"][variant]["binary_sha256"]
            ):
                raise RuntimeError(f"Incorrect binary fingerprint for {variant}")
        if client_fingerprint() != manifest["shared_client"]:
            raise RuntimeError("Shared driver/SDK/client sources changed")
        import measure

        original_collect = measure.collect
        (ROOT / "probes").mkdir(exist_ok=False)
        state["status"] = "running"
        write_json(ROOT / "measurement-state.json", state)
        for spec in state["plan"]:
            variant = spec["variant"]
            version, executable, _ = VARIANTS[variant]
            prefix = f"{spec['category']}-{variant}"
            run_id = f"{prefix}-r{spec['pair']}-{version}-{spec['interval_ms']}ms"
            state["active_run"] = run_id
            write_json(ROOT / "measurement-state.json", state)
            measure.PACKAGE = f"samples/apps/basic/{executable}"
            measure.DRIVER = DRIVER
            measure.collect = original_collect
            measure.MARKER_CALLBACK = None
            os.environ.pop("CCF_QUEUE_PROBE_OUT", None)
            os.environ.pop("CCF_QUEUE_ORIGINAL_DRIVER", None)
            gate = None
            if spec["category"] == "queue":
                gate = QueueGate(original_collect)
                measure.collect = gate.collect
                measure.MARKER_CALLBACK = gate.marker_callback
                measure.DRIVER = HERE / "queue_probe_driver.py"
                os.environ["CCF_QUEUE_ORIGINAL_DRIVER"] = str(DRIVER)
                os.environ["CCF_QUEUE_PROBE_OUT"] = str(ROOT / "probes" / run_id)
            result = None
            try:
                measure.wait_for_quiet(run_id)
                result = measure.run_one(
                    prefix, spec["pair"], version, spec["interval_ms"]
                )
                result.update(spec)
                if result["start_time"] <= manifest["all_builds_finished_at"]:
                    raise RuntimeError("A measurement overlapped the build phase")
                if (
                    result["binary_sha256"]
                    != manifest["variants"][variant]["binary_sha256"]
                ):
                    raise RuntimeError("Measurement used an unexpected executable")
                if gate:
                    gate.finish(result)
                else:
                    result["instrumented_timing"] = False
                result["shared_client_sha256"] = manifest["shared_client"]["sha256"]
                result["accepted"] = True
                results.append(result)
                state["completed_runs"] = len(results)
                write_json(ROOT / "results.json", results)
                write_json(ROOT / "paired-summary.json", paired_summary(results))
                print(
                    f"ACCEPTED {run_id} ({len(results)}/{len(state['plan'])})",
                    flush=True,
                )
            except BaseException as error:
                if result is not None:
                    result.update(
                        accepted=False,
                        error=f"{type(error).__name__}: {error}",
                    )
                raise
            finally:
                if gate:
                    gate.close()
                if result is not None:
                    write_json(ROOT / "runs" / run_id / "result.json", result)
        if not all(item["complete"] for item in paired_summary(results)):
            raise RuntimeError("Incomplete paired comparisons")
        for variant in VARIANTS:
            if (
                sha256(binary_path(variant))
                != manifest["variants"][variant]["binary_sha256"]
            ):
                raise RuntimeError(f"Executable changed during the matrix: {variant}")
        if client_fingerprint() != manifest["shared_client"]:
            raise RuntimeError(
                "Shared driver/SDK/client sources changed during the matrix"
            )
        state.update(status="complete", finished_at=time.time())
    except BaseException as error:
        state.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        write_json(ROOT / "measurement-state.json", state)


if __name__ == "__main__":
    main()
