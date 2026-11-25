# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Build and time ablation variants of the consensus replayer.

usage:
  ablation.py build PATCHES LEAN_CONSENSUS_DIR BINDIR
  ablation.py time BINDIR VALIDATOR OLD_VALIDATOR CAPTURES ROUNDS OUT.csv
  ablation.py report OUT.csv

Each variant uses the validator named by its VALIDATOR file (old: before the change).

`time` runs the CI step (VALIDATOR BINARY CAPTURES) once per variant per round, with the
variants interleaved, and records wall time, CPU time and peak RSS of the step's process
tree, its exit status, and a hash of its output.
"""
import csv, hashlib, os, pathlib, shutil, statistics, subprocess, sys, tempfile, time


def build(patches, lean, bindir):
    patches, lean, bindir = map(pathlib.Path, (patches, lean, bindir))
    bindir.mkdir(parents=True, exist_ok=True)
    for variant in sorted(patches.iterdir()):
        overlay = [p.relative_to(variant) for p in variant.rglob("*.lean")]
        saved = {p: (lean / p).read_text() for p in overlay}
        try:
            for p in overlay:
                (lean / p).write_text((variant / p).read_text())
            result = subprocess.run(
                ["lake", "build", "--wfail", "consensus-replay"],
                cwd=lean, capture_output=True, text=True, check=False,
            )
            if result.returncode != 0:
                sys.exit(f"{variant.name}:\n" + (result.stdout + result.stderr)[-4000:])
            shutil.copy(lean / ".lake/build/bin/consensus-replay", bindir / variant.name)
            shutil.copy(variant / "VALIDATOR", bindir / (variant.name + ".validator"))
        finally:
            for p, text in saved.items():
                (lean / p).write_text(text)
        print(f"built {variant.name}", flush=True)


def run(argv):
    with tempfile.TemporaryFile() as out:
        start = time.monotonic()
        pid = os.fork()
        if pid == 0:
            os.dup2(out.fileno(), 1)
            os.dup2(out.fileno(), 2)
            os.execvp(argv[0], argv)
        _, status, usage = os.wait4(pid, 0)
        wall = time.monotonic() - start
        out.seek(0)
        text = out.read()
    return (
        os.waitstatus_to_exitcode(status),
        hashlib.sha256(text).hexdigest()[:12],
        text.decode(errors="replace").strip().splitlines()[-1:],
        wall,
        usage.ru_utime + usage.ru_stime,
        usage.ru_maxrss // 1024,
    )


def timeit(bindir, validator, old_validator, captures, rounds, out):
    scripts = {"new": validator, "old": old_validator}
    runs = [
        (b.name, scripts[b.with_name(b.name + ".validator").read_text()], str(b))
        for b in sorted(pathlib.Path(bindir).iterdir())
        if b.suffix != ".validator"
    ]
    with open(out, "a", newline="") as fh:
        writer = csv.writer(fh)
        for rnd in range(int(rounds)):
            for name, script, binary in runs:
                code, digest, last, wall, cpu, rss = run(["python3", script, binary, captures])
                writer.writerow([rnd, name, code, digest, f"{wall:.2f}", f"{cpu:.2f}", rss])
                fh.flush()
                print(rnd, name, code, digest, f"wall={wall:.1f}s cpu={cpu:.1f}s rss={rss}MB", last, flush=True)


def report(out):
    rows = {}
    for rnd, name, code, digest, wall, cpu, rss in csv.reader(open(out)):
        rows.setdefault(name, []).append((int(code), digest, float(wall), float(cpu), int(rss)))
    names = sorted(rows)
    outputs = {(r[0], r[1]) for rs in rows.values() for r in rs}
    print("| Variant | Wall, median (range) / s | Gain over previous / s | Gain over original / s | CPU, median / s | Peak RSS / MB |")
    print("| --- | --- | --- | --- | --- | --- |")
    original = previous = None
    for name in names:
        rs = rows[name]
        walls = [r[2] for r in rs]
        wall = statistics.median(walls)
        original = wall if original is None else original
        step = "" if previous is None else f"{previous - wall:.1f}"
        print(
            f"| `{name}` | {wall:.1f} ({min(walls):.1f}-{max(walls):.1f}) | {step} "
            f"| {original - wall:.1f} | {statistics.median(r[3] for r in rs):.0f} | {max(r[4] for r in rs)} |"
        )
        previous = wall
    print(f"\n{len(rows[names[0]])} runs per variant; distinct (exit status, output) pairs: {len(outputs)} {sorted(outputs)}")


if __name__ == "__main__":
    {"build": build, "time": timeit, "report": report}[sys.argv[1]](*sys.argv[2:])
