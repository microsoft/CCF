# Blocking-mode performance investigation

## Handoff state

- Worktree: `/workspaces/CCF-blocking-perf`
- Branch: `blocking_perf_test`
- Base: `9dad6c650` (`main` when the worktree was created)
- Build: `RelWithDebInfo`, Ninja, `WORKER_THREADS=2`
- Source changes are uncommitted.
- Seven implementation files are modified, plus this handoff document.

The current blocking-test defaults are:

| Parameter                      |            Value |
| ------------------------------ | ---------------: |
| Logical sessions               |              320 |
| Sessions per submitter process |               32 |
| Submitter processes            |               10 |
| Requests per session           |            2,000 |
| Signature time interval        |              2ms |
| Signature transaction interval |            5,000 |
| Max writes ahead               |                0 |
| Node affinity                  | Unset by default |
| Client affinity                | Unset by default |

## Goal

The original `pi_basic_blocking` test was primarily a load test for blocking responses rather than a search for peak throughput. It ran every logical client as a separate process on the same machine as the CCF service. The investigation aimed to:

1. Establish a reliable baseline.
2. Determine whether signature cadence, the service, or Piccolo was limiting throughput.
3. Replace Piccolo's process-heavy client architecture if justified.
4. Sweep signature cadence, session count, and physical client-process count.
5. Test CPU isolation between the service and clients.

## Environment

The machine exposes:

- 32 logical CPUs
- 16 physical cores with SMT2
- One socket and one NUMA node
- SMT sibling pairs `(0,1)`, `(2,3)`, ..., `(30,31)`

Cgroup v2 is mounted read-only inside the container, so child cgroups and cpuset cgroups cannot be created. CPU isolation is therefore implemented with process/thread affinity:

- CCF node threads: `os.sched_setaffinity`
- Submitter processes: `taskset --cpu-list`

## Original baseline

The build reproduced the performance workflow exactly:

```bash
cmake -GNinja -DWORKER_THREADS=2 ..
ninja
```

Original test parameters:

- 128 client processes
- One synchronous TLS connection per process
- 100 blocking writes per client
- `--max-writes-ahead 0`
- Signature interval: 5,000 transactions or 100ms

Three baseline runs produced:

| Run |    Throughput |
| --- | ------------: |
| 1   | 1,213.24 tx/s |
| 2   | 1,196.39 tx/s |
| 3   | 1,193.58 tx/s |

Mean: **1,201.07 tx/s**. All runs had zero request errors.

This was already close to the timer-derived ceiling of approximately $128 / 0.1 = 1,280$ tx/s, indicating that the 100ms signature timer was the first-order limiter.

## Original client architecture

`tests/infra/basicperf.py` generated one parquet workload and launched one `submit` process per logical client. Each `submit` process:

- Loaded a parquet file.
- Opened one mTLS HTTP/1.1 connection.
- Sent requests synchronously when `max-writes-ahead=0`.
- Busy-spun through the existing OpenSSL BIO wrapper while waiting for socket progress.
- Wrote separate send and response parquet files.

At 128 clients, Python therefore launched 128 processes to obtain 128 concurrent blocking sessions. This created unnecessary process scheduling, file management, TLS setup, and CPU contention.

## Bottleneck confirmation

Keeping the old 128-process client but reducing the signature timer from 100ms to 20ms produced:

- **4,846.06 tx/s**
- Timer-derived ceiling: approximately 6,400 tx/s

The 24% shortfall showed that client/service overhead became material once signature cadence increased.

## Client redesign

A new opt-in `--multi-session` mode was added to `submit`.

### Transport

The new path uses CCF's existing libcurl-multi/libuv integration:

- One easy handle and persistent mTLS HTTP/1.1 connection per logical session.
- One blocking request in flight per logical session.
- Socket-readiness-driven sleeping rather than BIO retry spinning.
- Multiple logical sessions per process.
- Existing synchronous submitter behavior remains available for pipelined and failover tests.

### Workload and result compatibility

BasicPerf now:

- Adds a `sessionID` to generated input parquet rows.
- Prefixes message IDs with the logical client name to keep them globally unique.
- Concatenates logical-client workloads into process batches.
- Preserves the existing send/response parquet output schemas.
- Reconstructs per-logical-client metrics during analysis.

Both Arrow `string`/`large_string` and `binary`/`large_binary` input columns are accepted because large combined workloads promote column widths.

### Persistent connection pool

An important intermediate failure was found:

- 128 transfers were concurrently active.
- 64,000 requests used 8,150 local TCP ports.
- Throughput was only about 1.6-1.8k tx/s.

The curl multi-handle's connection cache was evicting idle connections between completion waves. Explicitly sizing the active and idle connection limits to the logical session count fixed this:

- 128 sessions used exactly 128 TCP ports.
- The same 20ms test reached **5,939.74 tx/s**.
- This was 22.6% faster than the old 128-process result at the same cadence.

### Additional controls and reporting

Added controls include:

- `BLOCKING_PERF_CLIENT_COUNT`
- `BLOCKING_PERF_CLIENTS_PER_PROCESS`
- `BLOCKING_PERF_ITERATIONS`
- `BLOCKING_PERF_SIG_TX_INTERVAL`
- `BLOCKING_PERF_SIG_MS_INTERVAL`
- `BLOCKING_PERF_NODE_CPU_AFFINITY`
- `BLOCKING_PERF_CLIENT_CPU_AFFINITY`

BasicPerf now reports p50, p90, and p99 latency in microseconds in `statistics.json`.

## Parameter sweeps

### Signature timer and session count

A coarse sweep showed the expected signature-limited region followed by saturation:

| Sessions | 100ms |   20ms |    5ms |    1ms |
| -------: | ----: | -----: | -----: | -----: |
|       32 |   319 |  1,561 |  5,928 |  6,677 |
|       64 |   629 |  3,045 | 11,126 | 11,422 |
|      128 | 1,236 |  5,719 | 14,341 | 17,354 |
|      256 | 2,393 | 10,306 | 17,499 | 19,141 |

Values are tx/s. These runs used one event-driven submitter process.

A finer one-process sweep found a short-run best of **18,677.89 tx/s** at 256 sessions and a 2ms signature timer. More sessions regressed because one client event loop and the service were saturated.

### Submitter process count

Holding 256 logical sessions fixed showed that one event loop had become a client-side bottleneck:

| Processes | Sessions/process |    1ms |    2ms |
| --------: | ---------------: | -----: | -----: |
|         1 |              256 | 18,821 | 18,318 |
|         2 |              128 | 27,241 | 27,180 |
|         4 |               64 | 26,565 | 27,161 |
|         8 |               32 | 25,330 | 27,940 |

Values are tx/s. A small number of event-driven processes is substantially better than either one event loop or the original hundreds of processes.

### Service saturation

With 32 sessions per process and a 2ms signature timer:

| Sessions | Processes |  Throughput |
| -------: | --------: | ----------: |
|      128 |         4 | 21,320 tx/s |
|      192 |         6 | 22,026 tx/s |
|      256 |         8 | 25,339 tx/s |
|      320 |        10 | 26,786 tx/s |
|      384 |        12 | 26,493 tx/s |
|      512 |        16 | 22,563 tx/s |

The useful saturation region is around 256-320 logical sessions. Higher concurrency adds scheduling pressure without increasing throughput.

### Repeated final candidate

Three 320-session, 10-process runs produced:

- 29,794.50 tx/s
- 27,722.06 tx/s
- 29,204.47 tx/s

Mean: **28,907.01 tx/s**. Median: **29,204.47 tx/s**. CV: **3.02%**.

A later hardened end-to-end run produced:

- **27,518.37 tx/s**
- p50: 9.263ms
- p90: 12.616ms
- p99: 72.901ms
- 640,000 successful requests
- Zero errors

This is a **22.91x** improvement over the original 1,201.07 tx/s mean.

## Signature transaction interval

A count-driven sweep used a deliberately slow 1,000ms time interval. Throughput increased through a transaction interval near 20, then fell. At an interval of 500, the test exceeded its 300s client timeout.

This is a liveness interaction specific to blocking clients: when the transaction threshold exceeds the number of sessions that can each submit one request, all clients wait for commit responses and cannot generate enough additional transactions to reach the threshold. The time-based signature eventually releases them, but a 1,000ms timer makes progress too slow to be useful.

For this workload, the 2ms time interval is both faster and easier to reason about than trying to drive signatures primarily by transaction count.

## CPU affinity reconfirmation

The original affinity experiment used physically disjoint cores:

- Node: logical CPUs `0-7`, physical cores 0-3
- Clients: logical CPUs `8-31`, physical cores 4-15

A single earlier run suggested pinning was 0.85% slower. This did **not** hold when reconfirmed on the final 320-session workload.

Five interleaved pinned and five unpinned runs produced:

| Mode     |        Mean | Median |         Range |    CV | Mean p50 | Mean p90 | Mean p99 |
| -------- | ----------: | -----: | ------------: | ----: | -------: | -------: | -------: |
| Pinned   | 29,135 tx/s | 28,924 | 28,738-29,958 | 1.68% |  9.232ms | 11.745ms | 59.186ms |
| Unpinned | 28,465 tx/s | 28,433 | 27,392-29,968 | 3.57% |  9.311ms | 12.445ms | 57.200ms |

Live `/proc` sampling confirmed:

- Pinned: all four node threads allowed only on `0-7`; all ten submitters allowed only on `8-31`.
- Unpinned: node threads and all submitters allowed on `0-31`, with observed overlap in the upper CPU range.

Pinning was 2.36% faster on average and substantially less variable. The paired mean difference was +670.61 tx/s, but its 95% confidence interval was `[-688.95, +2030.16]` tx/s. Five pairs therefore do not prove a throughput improvement, but they do show that pinning is at least neutral on this workload and likely improves repeatability.

Affinity remains optional and is unset in the source defaults.

## Modified files

- `CMakeLists.txt`
  - Exposes blocking-perf cache parameters.
  - Sets the measured 320-session/10-process/2ms defaults.
- `tests/infra/basicperf.py`
  - Batches logical sessions into physical processes.
  - Preserves logical-client analysis.
  - Adds affinity controls and latency percentiles.
- `tests/perf-system/submitter/submit.cpp`
  - Adds the event-driven multi-session submitter.
  - Handles combined Arrow column widths.
  - Preserves output parquet compatibility.
- `tests/perf-system/submitter/handle_arguments.h`
  - Adds `--multi-session`.
- `tests/perf-system/submitter/parquet_data.h`
  - Tracks input session IDs.
- `tests/perf-system/submitter/CMakeLists.txt`
  - Links `submit` with curl and libuv.
- `src/http/curl.h`
  - Allows completed requests to transfer easy handles.
  - Exposes explicit multi-handle connection-pool sizing.

## Validation completed

- Full incremental Ninja rebuild: 231 affected targets passed.
- Final optimized `pi_basic_blocking`: passed with zero request errors.
- Legacy one-session synchronous path: passed.
- Curl fixture suite via `tests/e2e_curl.py`: 15/15 tests and 342/342 assertions passed.
- C++ formatting: passed.
- Python formatting and linting: passed.
- CMake formatting: passed.
- ASCII, copyright, and Git whitespace checks: passed.

The repository's broad `scripts/cpp-format-checks.sh -f` behaved incorrectly in this worktree and reformatted 114 unrelated files. That churn was reverted. Targeted `clang-format` was used for the intended C++ files, and the final implementation diff was limited to the seven files above before this document was added.

## Retained artifacts

All sweep data and verbose logs are under `/workspaces/CCF-blocking-perf/build`.

Key summaries:

- `blocking-time-sweep.tsv`
- `blocking-peak-sweep.tsv`
- `blocking-process-sweep.tsv`
- `blocking-session-process-sweep.tsv`
- `blocking-repeat-sweep.tsv`
- `taskset-reconfirm.tsv`

Key final logs:

- `blocking-final-hardened.log`
- `blocking-legacy-compat.log`
- `e2e-curl.log`
- `taskset-reconfirm-pinned-proof.log`
- `taskset-reconfirm-{pinned,unpinned}-{1..5}.log`

The build cache was restored to unpinned affinity values after the taskset experiment.

## Suggested next steps

1. Review whether the two small additions to shared `src/http/curl.h` should remain generic APIs or move behind a submitter-specific wrapper.
2. Add focused automated tests for combined parquet inputs and multi-session connection persistence.
3. Consider recording process/session/signature parameters in Bencher output so historical results remain comparable after changing defaults.
4. Decide whether CI should pin CPUs. Current data favors pinning for repeatability, but five paired samples are not statistically conclusive for throughput.
5. Review and commit the seven implementation files and this handoff document in coherent commits.
