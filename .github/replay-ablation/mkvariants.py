# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Generate ablation variants of the consensus replayer.

Each variant is the optimised replayer (FULL) with exactly one optimisation removed, as
files to overlay on lean/consensus. `unoptimised` is the replayer before the change.
usage: mkvariants.py REPO FULL_REV OUTDIR
"""
import pathlib, subprocess, sys

repo, FULL, outdir = sys.argv[1:]
R = "lean/consensus/Consensus/Replay/"
BASE = "f6d7d21c0"


def show(rev, name):
    return subprocess.check_output(["git", "-C", repo, "show", f"{rev}:{R}{name}"], text=True)


full = {n: show(FULL, n) for n in ("Input.lean", "Interpreter.lean", "Reduction.lean")}
old = {n: show(BASE, n) for n in full}


def sub(text, a, b, count=1):
    assert text.count(a) == count, (text.count(a), a[:80])
    return text.replace(a, b)


def between(text, start, end):
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]


variants = {}

# (a1) streaming: read the whole file and split it, instead of reading line by line.
t = full["Input.lean"]
t = sub(t, """  let handle ← IO.FS.Handle.mk path .read
""", """  let content ← IO.FS.readFile path
  let lines := (content.splitOn "\\n").toArray
  let lines := if content.endsWith "\\n" then lines.pop else lines
  let mut cursor : Nat := 0
""")
t = sub(t, """    let raw ← handle.getLine
    if raw.isEmpty then
      break
""", """    if cursor >= lines.size then
      break
    let raw := lines[cursor]!
    cursor := cursor + 1
""")
variants["no-streaming"] = {"Input.lean": t}

# (a2) skipping non-ccf.cft lines before JSON parsing.
t = sub(full["Input.lean"], """        if tag != "ccf.cft" then
          .skip
        else if""", """        if tag != "ccf.cft" then
          .fallback
        else if""")
variants["no-tag-skip"] = {"Input.lean": t}

# (a) whole scanner: every line takes the full JSON parse (implies no msg reuse, no snapshot skip).
t = sub(full["Input.lean"], """private def matchFluentdLine (raw : String) : FastLine :=
  if !byteEqAt raw 0""", """private def matchFluentdLine (raw : String) : FastLine :=
  if true || !byteEqAt raw 0""")
variants["no-scanner"] = {"Input.lean": t}

# (b) reuse of the parsed msg for byte-identical consecutive events (implies no snapshot skip).
t = sub(full["Input.lean"], "            if cachedRaw == msgRaw then", "            if false && cachedRaw == msgRaw then")
variants["no-msg-reuse"] = {"Input.lean": t}

# (c) per-pid buckets with qsort and per-node HashMap -> one global merge sort and per-node filter.
t = full["Input.lean"]
body = between(t, "private def buildStreamsFromBuckets", "/--\nOrder each process's records")
new_body = '''private def buildStreamsFromBuckets (buckets : Std.HashMap String (Array BucketEntry))
    : Except String (Array (Array Event) × List String) := do
  let keyed : List (String × BucketEntry) :=
    buckets.toList.flatMap fun (pid, entries) => entries.toList.map (pid, ·)
  let keyed :=
    keyed.mergeSort
      fun (p, a) (q, b) =>
        p < q || (p == q && (a.m_ts < b.m_ts || (a.m_ts == b.m_ts && a.line <= b.line)))
  let mut events : Array Event := #[]
  let mut pids : Std.HashMap String String := {}
  let mut declared : List String := []
  let mut parsedCache : Std.HashMap Nat ParsedMessage := {}
  let mut previous : Option (String × Nat × String × Nat) := none
  for (pid, entry) in keyed do
    let location := s!"{entry.file}:{entry.line}"
    if let some (lastPid, lastMts, earlierFile, earlierLine) := previous then
      if lastPid == pid && lastMts == entry.m_ts then
        throw
          s!"{location}: m_ts {entry.m_ts} of pid '{pid}' repeats {earlierFile}:{earlierLine}"
    previous := some (pid, entry.m_ts, entry.file, entry.line)
    let parsed ←
      match entry.stateId.bind (parsedCache[·]?) with
      | some cached => pure cached
      | none =>
          let parsed ← (parseMessage entry.message).mapError (s!"{location}: " ++ ·)
          if let some id := entry.stateId then
            parsedCache := parsedCache.insert id parsed
          pure parsed
    unless parsed.isCmd do
      if let some other := pids[parsed.node]? then
        unless other == pid do
          throw
            s!"{location}: node '{parsed.node}' is traced by pids '{other}' and '{pid}'"
      pids := pids.insert parsed.node pid
      let record : Record :=
        { file := entry.file, line := entry.line, value := Json.null }
      events :=
        events.push
          {
            record
            m_ts := entry.m_ts
            ts := entry.ts
            function := parsed.function
            node := parsed.node
            message := entry.message
            state := parsed.state
            stateId := entry.stateId
          }
      declared := parsed.node :: parsed.extraDeclared ++ declared
  let streams :=
    pids.keys.mergeSort.toArray.map fun node => events.filter (·.node == node)
  return (streams, declared.mergeSort.eraseDups)

'''
variants["no-buckets"] = {"Input.lean": sub(t, body, new_body)}

# (e) skip of an already-verified identical snapshot.
I = full["Interpreter.lean"]
variants["no-snapshot-skip"] = {"Interpreter.lean": sub(
    I, "        if stateId.isSome && cache.lastVerifiedId == stateId then",
    "        if false && stateId.isSome && cache.lastVerifiedId == stateId then")}

# (d1) per-node cache: rebuild the one-pass summary at every observation (implies no snapshot skip).
no_cache = sub(I, """    : Except String ReplayState := do
  let self ← header.nodeId node
  if self < replay.obsCache.size then""", """    : Except String ReplayState := do
  let self ← header.nodeId node
  if false && self < replay.obsCache.size then""")
variants["no-obs-cache"] = {"Interpreter.lean": no_cache}

# (d2) additionally derive the observed fields from the model definitions, as before the change.
start, end = "/-- Compare an action-boundary snapshot with the current model node. -/", "/-- Physical packet coordinates"
old_observe = between(old["Interpreter.lean"], start, end)
t = sub(no_cache, between(no_cache, start, "private def observeStateCached"), old_observe)
variants["no-obs-cache-no-one-pass"] = {"Interpreter.lean": t}

# (f) node-id HashMap index.
variants["no-node-index"] = {"Interpreter.lean": sub(I, """      ({} : Std.HashMap String NodeID)
  { header with nodeIds }""", """      ({} : Std.HashMap String NodeID)
  if true then header else { header with nodeIds }""")}

# (g) scheduler fast path, optional group recording and incremental counters.
loop_new = between(I, "  let mut actions : Nat := 0\n  let mut observations : Nat := 0\n  for _ in [:total] do", "end Consensus.Replay")
loop_old = between(old["Interpreter.lean"], "  for _ in [:total] do", "end Consensus.Replay")
loop_old = sub(loop_old, "    modify (·.push group)\n", "    if record || true then\n      modify (·.push group)\n")
variants["no-sched-fast-path"] = {"Interpreter.lean": sub(I, loop_new, loop_old)}

# empty send observation shortcut.
variants["no-empty-sends-shortcut"] = {"Interpreter.lean": sub(I, """      if sends.isEmpty && replay.queued.isEmpty then
        return replay
""", "")}

# (h) rule dispatch on the head event's function.
Rn, Ro = full["Reduction.lean"], old["Reduction.lean"]
variants["no-rule-dispatch"] = {"Reduction.lean": sub(
    Rn, between(Rn, "def ruleStep", "end Consensus.Replay.Reducer"),
    between(Ro, "def ruleStep", "end Consensus.Replay.Reducer"))}

variants = {
    name: {"Consensus/Replay/" + f: text for f, text in files.items()}
    for name, files in variants.items()
}
variants["unoptimised"] = {
    path: subprocess.check_output(
        ["git", "-C", repo, "show", f"{BASE}:lean/consensus/{path}"], text=True
    )
    for path in [
        "Consensus/Replay/Groups.lean",
        "Consensus/Replay/Input.lean",
        "Consensus/Replay/Interpreter.lean",
        "Consensus/Replay/Reduction.lean",
        "replay/ReplayMain.lean",
    ]
}
variants["full"] = {}
for name, files in variants.items():
    d = pathlib.Path(outdir) / name
    d.mkdir(parents=True, exist_ok=True)
    for f, text in files.items():
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        (d / f).write_text(text)
print("\n".join(variants))
