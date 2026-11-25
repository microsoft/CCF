# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Generate ablation variants of the consensus replayer.

Cumulative variants: the replayer before the change (`00-original`), then the optimisations
added one at a time in ORDER, each variant including all earlier ones, ending at FULL.
Variant k is FULL with the optimisations after k removed, as files to overlay on
lean/consensus, plus a VALIDATOR file naming the tests/cft_trace_validation.py to use.
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

OBSERVE_START = "/-- Compare an action-boundary snapshot with the current model node. -/"


def rm_streaming(t):
    t = sub(t, """  let handle ← IO.FS.Handle.mk path .read
""", """  let content ← IO.FS.readFile path
  let lines := (content.splitOn "\\n").toArray
  let lines := if content.endsWith "\\n" then lines.pop else lines
  let mut cursor : Nat := 0
""")
    return sub(t, """    let raw ← handle.getLine
    if raw.isEmpty then
      break
""", """    if cursor >= lines.size then
      break
    let raw := lines[cursor]!
    cursor := cursor + 1
""")


def rm_tag_skip(t):
    return sub(t, """        if tag != "ccf.cft" then
          .skip
        else if""", """        if tag != "ccf.cft" then
          .fallback
        else if""")


def rm_scanner(t):
    return sub(t, """private def matchFluentdLine (raw : String) : FastLine :=
  if !byteEqAt raw 0""", """private def matchFluentdLine (raw : String) : FastLine :=
  if true || !byteEqAt raw 0""")


def rm_msg_reuse(t):
    return sub(t, "            if cachedRaw == msgRaw then", "            if false && cachedRaw == msgRaw then")


def rm_buckets(t):
    return sub(t, between(t, "private def buildStreamsFromBuckets", "/--\nOrder each process's records"), new_body)


def rm_snapshot_skip(t):
    return sub(t, "        if stateId.isSome && cache.lastVerifiedId == stateId then",
               "        if false && stateId.isSome && cache.lastVerifiedId == stateId then")


def rm_obs_cache(t):
    return sub(t, """    : Except String ReplayState := do
  let self ← header.nodeId node
  if self < replay.obsCache.size then""", """    : Except String ReplayState := do
  let self ← header.nodeId node
  if false && self < replay.obsCache.size then""")


def rm_one_pass(t):
    old_observe = between(old["Interpreter.lean"], OBSERVE_START, "/-- Physical packet coordinates")
    return sub(t, between(t, OBSERVE_START, "private def observeStateCached"), old_observe)


def rm_node_index(t):
    return sub(t, """      ({} : Std.HashMap String NodeID)
  { header with nodeIds }""", """      ({} : Std.HashMap String NodeID)
  if true then header else { header with nodeIds }""")


def rm_sched_fast_path(t):
    loop_new = between(t, "  let mut actions : Nat := 0\n  let mut observations : Nat := 0\n  for _ in [:total] do", "end Consensus.Replay")
    loop_old = between(old["Interpreter.lean"], "  for _ in [:total] do", "end Consensus.Replay")
    loop_old = sub(loop_old, "    modify (·.push group)\n", "    if record || true then\n      modify (·.push group)\n")
    return sub(t, loop_new, loop_old)


def rm_empty_sends(t):
    return sub(t, """      if sends.isEmpty && replay.queued.isEmpty then
        return replay
""", "")


def rm_rule_dispatch(t):
    return sub(t, between(t, "def ruleStep", "end Consensus.Replay.Reducer"),
               between(old["Reduction.lean"], "def ruleStep", "end Consensus.Replay.Reducer"))


# (name, file, removal). A step's prerequisites come before it; otherwise largest gain first.
ORDER = [
    ("one-pass-summary", "Interpreter.lean", rm_one_pass),
    ("obs-cache", "Interpreter.lean", rm_obs_cache),
    ("line-scanner", "Input.lean", rm_scanner),
    ("msg-reuse", "Input.lean", rm_msg_reuse),
    ("snapshot-skip", "Interpreter.lean", rm_snapshot_skip),
    ("rule-dispatch", "Reduction.lean", rm_rule_dispatch),
    ("streaming", "Input.lean", rm_streaming),
    ("sched-fast-path", "Interpreter.lean", rm_sched_fast_path),
    ("largest-first", None, None),
    ("buckets", "Input.lean", rm_buckets),
    ("tag-skip", "Input.lean", rm_tag_skip),
    ("empty-sends-shortcut", "Interpreter.lean", rm_empty_sends),
    ("node-index", "Interpreter.lean", rm_node_index),
]

out = pathlib.Path(outdir)


def write(name, files, validator):
    d = out / name
    for f, text in files.items():
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        (d / f).write_text(text)
    d.mkdir(parents=True, exist_ok=True)
    (d / "VALIDATOR").write_text(validator)
    print(name, validator, sorted(files))


write("00-original", {
    path: subprocess.check_output(["git", "-C", repo, "show", f"{BASE}:lean/consensus/{path}"], text=True)
    for path in [
        "Consensus/Replay/Groups.lean",
        "Consensus/Replay/Input.lean",
        "Consensus/Replay/Interpreter.lean",
        "Consensus/Replay/Reduction.lean",
        "replay/ReplayMain.lean",
    ]
}, "old")
# k = 0 is FULL with every optimisation removed; k = len(ORDER) is FULL.
for k in range(len(ORDER) + 1):
    texts = {}
    validator = "old"
    for i, (name, f, removal) in enumerate(ORDER):
        if f is None:
            validator = "new" if i < k else "old"
        elif i >= k:
            texts[f] = removal(texts.get(f, full[f]))
    label = "all-removed" if k == 0 else "plus-" + ORDER[k - 1][0]
    write(f"{k + 1:02d}-{label}", {"Consensus/Replay/" + f: t for f, t in texts.items()}, validator)
