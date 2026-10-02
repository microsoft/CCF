// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Lays out the dumps that `disaster-recovery-replay --dump` writes. Every
// semantic fact shown comes from a dump; this script only groups, filters and
// renders it, and diffs consecutive dumped states to highlight changes.

"use strict";

const [LEFT, RIGHT, DOT, CHECK, CROSS, DASH] = [
  "\u2190",
  "\u2192",
  "\u00B7",
  "\u2713",
  "\u2717",
  "\u2013",
];
const KINDS = ["retry", "gossip", "vote", "iamopen", "timeout"];
const TICK = { retry: 3, receive: 5, timeout: 8 };
const GUARDS = {
  queued: "envelope queued",
  active: "node active",
  known: "node in the network",
  localStep: "local step enabled",
};

// A small vocabulary of glyphs, each with one meaning wherever it appears, and
// a title. Emoji, marked true, are drawn in grey, so that colour only marks
// change and failure. Pictographs that also have a text presentation carry
// U+FE0F, to render as full-size emoji; the phases are text glyphs, so
// joining's arrow carries U+FE0E to match them.
const GLYPHS = {
  // Messages, and the actions that send them or time out.
  gossip: ["\u{1F4AC}", "gossip: carries the sender's recovered TxID", true],
  vote: ["\u2709\uFE0F", "vote: for the node that the sender chose", true],
  iamopen: ["\u{1F4E3}", "IAmOpen: the sender has opened", true],
  retry: ["\u{1F504}", "retry: the node sends its messages again", true],
  timeout: ["\u23F1\uFE0F", "timeout: the node's timer fired", true],
  // Phases, filling up as a node advances.
  gossiping: ["\u25D4", "phase gossiping: collecting recovered TxIDs"],
  voting: ["\u25D1", "phase voting: collecting votes for the chosen node"],
  opening: ["\u25D5", "phase opening: the node is opening"],
  open: ["\u25CF", "phase open"],
  joining: [
    "\u21AA\uFE0E",
    "phase joining: the node will join the chosen node",
  ],
  // Notifications.
  opens: ["\u{1F513}", "notification opening: the node opens", true],
  restart: ["\u21BB", "restart: the node restarts to join the chosen node"],
  completed: ["\u{1F3C1}", "notification completed: the node is open", true],
  rejected: ["\u2298", "notification rejected: the node rejected a message"],
  // How the replay went.
  ok: ["\u2713", "replayed, and its checks passed"],
  failed: ["\u2717", "failed here"],
  skipped: ["\u2013", "not replayed: the replay stopped before it"],
};

const ui = {
  runs: [],
  cache: new Map(),
  run: null,
  step: -1,
  mode: "steps",
  hidden: new Set(), // the nodes and kinds filtered out, as "node 0", "kind retry"
  recordOpen: new Map(), // records opened or closed by hand
  focusRecord: -1, // the record last clicked
};

const $ = (selector) => document.querySelector(selector);
const esc = (v) =>
  String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
const clamp = (v, low, high) => Math.max(low, Math.min(high, v));
const char = (key) => (GLYPHS[key] || [""])[0];
const list = (items, render) => `[${items.map(render).join(", ")}]`;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// A glyph with a title: its own, unless `title` is given.
function glyph(key, title) {
  const [g, own, emoji] = GLYPHS[key] || [];
  return g
    ? `<span class="g${emoji ? " emoji" : ""}" title="${esc(title || own)}">${g}</span>`
    : "";
}

// The text of some HTML, as titles and tooltips show it: an element with a
// data-text attribute stands for that text.
const scratch = document.createElement("template");
function plain(html) {
  scratch.innerHTML = html;
  for (const e of scratch.content.querySelectorAll("[data-text]"))
    e.replaceWith(e.dataset.text);
  return scratch.content.textContent;
}

// A value in brief: none, [a, b], {k:v k:v} for pairs, or JSON.
function fmt(v) {
  if (v === null || v === undefined) return "none";
  if (!Array.isArray(v))
    return typeof v === "object" ? JSON.stringify(v) : String(v);
  if (v.length && v.every((e) => Array.isArray(e) && e.length === 2))
    return `{${v.map(([k, e]) => `${k}:${e}`).join(" ")}}`;
  return `[${v.map(fmt).join(", ")}]`;
}

const phaseHtml = (p) => (GLYPHS[p] ? `${glyph(p)} ${esc(p)}` : esc(fmt(p)));

// A phase as records name it, e.g. "Voting".
const recordPhase = (name) =>
  glyph(String(name).toLowerCase(), "phase " + name) || esc(name);

// A message's route, acting node first: its glyph, then "0 -> 1, 2 (2.21)" for a
// send, or "0 <- 2 (2.21)" for a receive, with arrows.
const route = (message, actor, arrow, others, txid) =>
  `${glyph(message) || esc(message)} ${esc(`${actor} ${arrow} ${others}${txid ? ` (${txid})` : ""}`)}`;
const sendHtml = (m, sender) =>
  route(m.message, sender, RIGHT, m.target, m.txid);

// A retry's sends, grouped by message: "(vote) 0 -> 2; (gossip) 0 -> 0, 1, 2 (2.21)".
function sentHtml(sent, sender) {
  const groups = [];
  for (const m of sent) {
    const g = groups.find((g) => g.message === m.message && g.txid === m.txid);
    if (g) g.targets.push(m.target);
    else groups.push({ ...m, targets: [m.target] });
  }
  return groups
    .map((g) => route(g.message, sender, RIGHT, g.targets.join(", "), g.txid))
    .join("; ");
}

// A notification, and the fuller text that tooltips show for it.
function noteHtml(note) {
  const key = note.kind === "opening" ? "opens" : note.kind;
  const { openKind, chosen, reason } = note;
  const [what, title] =
    {
      opening: [openKind, `notification opening, by ${openKind}`],
      restart: [chosen, `notification restart, to join node ${chosen}`],
      rejected: [reason, `notification rejected: ${reason}`],
    }[note.kind] || [];
  const rest = what === undefined ? "" : " " + what;
  const cls = note.kind === "rejected" ? ' class="note"' : "";
  return `<span${cls} data-text="${esc(`${char(key)} ${note.kind}${rest}`)}">${glyph(key, title) || esc(note.kind)}${esc(rest)}</span>`;
}

// A value as the checks compare it, with phases, sends and notifications as
// glyphs. Sends need their `sender`.
function valueHtml(key, value, sender) {
  if (key === "phase" || key === "timeoutState") return phaseHtml(value);
  if (key === "sent" && Array.isArray(value))
    return list(value, (m) => sendHtml(m, sender));
  if (key === "notifications" && Array.isArray(value))
    return list(value, noteHtml);
  return esc(fmt(value));
}

// A raw record, abbreviated but complete. Node and sequence have their own
// column and the glyph stands for the kind; then come the route, @version, the
// phases pre->post and the timeout lane's, and every other field by name.
function recordHtml(v) {
  const shown = new Set(["node", "sequence", "kind"]);
  const parts = [];
  const has = (...keys) => keys.every((k) => v[k] !== undefined);
  const take = (html, ...keys) => {
    parts.push(html);
    keys.forEach((k) => shown.add(k));
  };
  const kind = String(v.kind).replace("_accepted", "");
  if (v.kind === "send" && has("message", "target"))
    take(sendHtml(v, v.node), "message", "target", "txid");
  else if (has("source"))
    take(route(kind, v.node, LEFT, v.source, v.txid), "source", "txid");
  else take(glyph(kind) || esc(v.kind));
  if (has("batch")) take(esc("batch " + v.batch), "batch");
  if (has("pre_version"))
    take(
      `<span title="the retry read sm_state at version ${esc(v.pre_version)}">@${esc(v.pre_version)}</span>`,
      "pre_version",
    );
  if (has("version")) {
    const tip =
      v.kind === "start"
        ? `the protocol started at version ${v.version}`
        : `CCF reported version ${v.version}: the one this execution committed at if it wrote, or read at if not`;
    take(`<span title="${esc(tip)}">@${esc(v.version)}</span>`, "version");
  }
  if (has("pre", "post"))
    take(recordPhase(v.pre) + RIGHT + recordPhase(v.post), "pre", "post");
  if (has("pre_timeout", "post_timeout"))
    take(
      `${glyph("timeout", "timeout lane")}${recordPhase(v.pre_timeout)}${RIGHT}${recordPhase(v.post_timeout)}`,
      "pre_timeout",
      "post_timeout",
    );
  for (const [key, item] of Object.entries(v)) {
    if (shown.has(key)) continue;
    if (key === "restart" && item === true)
      parts.push(glyph("restart", "the node requested a restart") + " restart");
    else parts.push(esc(key + "=" + fmt(item)));
  }
  return parts.join(" ");
}

// The shortest names that tell the logs apart.
function shortNames(files) {
  if (files.length < 2)
    return new Map(files.map((f) => [f, f.replace(/^.*[_/]/, "")]));
  let prefix = files[0];
  for (const f of files)
    while (!f.startsWith(prefix)) prefix = prefix.slice(0, -1);
  prefix = prefix.replace(/[^_/.-]*$/, "");
  return new Map(files.map((f) => [f, f.slice(prefix.length) || f]));
}

const originText = (run, o) =>
  `${run.shortName.get(o.file) || o.file}:${o.line}`;
const messageKey = (e) => e.message + (e.txid ? " " + e.txid : "");
const nodeIn = (run, state, node) =>
  state ? state.nodes[run.slot.get(node)] : null;
const isActive = (run, node) =>
  !run.states.length || run.states[0].active.includes(node);
const visible = (s) =>
  !ui.hidden.has("node " + s.node) && !ui.hidden.has("kind " + s.kind);

// Groups the dumped instructions into steps, those that come from the same
// records: one action and the observations around it.
function prepare(meta, dump) {
  const { instructions: ins = [], states = [], records = [] } = dump;
  const at = (o) => o.file + ":" + o.line;
  const recordAt = new Map(records.map((r, i) => [at(r), i]));
  const nodes = dump.header
    ? dump.header.expectedLocations
    : [...new Set(records.map((r) => String(r.value.node)))];
  const slot = new Map(
    (states[0] || { nodes: [] }).nodes.map((n, j) => [n.node, j]),
  );
  const steps = [];
  const stepOf = [];
  ins.forEach((x, i) => {
    const origin = x.origins.map(at).join(" ");
    const last = steps[steps.length - 1];
    if (!last || last.origin !== origin)
      steps.push({ index: steps.length, origin, ins: [], node: x.node });
    steps[steps.length - 1].ins.push(i);
    stepOf[i] = steps.length - 1;
  });
  let reached = 0;
  for (const s of steps) {
    const xs = s.ins.map((i) => ins[i]);
    const ran = xs.filter((x) => x.status !== "skipped");
    s.status = xs.some((x) => x.status === "failed")
      ? "failed"
      : ran.length
        ? "ok"
        : "skipped";
    s.action = s.ins.find((i) => ins[i].kind === "action");
    s.prev = reached;
    s.state = ran.length ? ran[ran.length - 1].state : null;
    if (s.state !== null) reached = s.state;
    const a = s.action === undefined ? null : ins[s.action].action;
    s.kind = !a ? "other" : a.kind === "deliver" ? a.message : a.kind;
    const origins = xs.flatMap((x) =>
      x.origins.map((o) => recordAt.get(at(o))),
    );
    s.records = [...new Set(origins)].filter((r) => r !== undefined);
  }
  // Which delivery took each send, from the dumped `consumed` of deliveries.
  const takenBy = new Map();
  const takerOfRecord = new Map();
  for (const s of steps) {
    const c = s.action === undefined ? null : ins[s.action].consumed;
    if (!c) continue;
    s.from = stepOf[c.sentBy];
    takenBy.set(c.sentBy + "/" + c.position, s.index);
    if (!c.record) continue;
    s.fromRecord = recordAt.get(at(c.record));
    takerOfRecord.set(s.fromRecord, s.index);
  }
  for (const s of steps) {
    const outputs = s.action === undefined ? null : ins[s.action].outputs;
    if (outputs)
      s.to = outputs.sent.map((_, k) => takenBy.get(s.action + "/" + k));
  }
  const series = (f) =>
    steps.map((s) => (s.state === null ? null : f(states[s.state])));
  const counts = (key) =>
    nodes.map((n) => series((st) => st.nodes[slot.get(n)].state[key].length));
  const order = (key) => KINDS.indexOf(key.split(" ")[0]);
  const messageKeys = [
    ...new Set(
      states.flatMap((st) => st.network.map((e) => messageKey(e.envelope))),
    ),
  ].sort((a, b) => order(a) - order(b) || (a < b ? -1 : a > b ? 1 : 0));
  const files = [...new Set(records.map((r) => r.file))];
  return {
    meta,
    dump,
    ins,
    states,
    records,
    nodes,
    slot,
    files,
    shortName: shortNames(files),
    recordAt,
    steps,
    stepOf,
    takerOfRecord,
    stepOfRecord: new Map(
      steps.flatMap((s) => s.records.map((r) => [r, s.index])),
    ),
    sparks: {
      gossips: counts("gossips"),
      votes: counts("votes"),
      flight: series((st) => st.network.reduce((sum, e) => sum + e.count, 0)),
    },
    messageKeys,
    failedStep: steps.findIndex((s) => s.status === "failed"),
  };
}

// Records that the failure names: the failing instruction's origins, or the
// log locations that a reduction failure's message mentions.
function failingRecords(run) {
  const failed = run.ins.find((x) => x.status === "failed");
  const named = failed ? failed.origins.map((o) => o.file + ":" + o.line) : [];
  const message = run.dump.outcome.message || "";
  for (const file of run.files)
    for (const rest of message.split(file + ":").slice(1)) {
      const line = /^\d+/.exec(rest);
      if (line) named.push(file + ":" + line[0]);
    }
  const found = named.map((k) => run.recordAt.get(k));
  return new Set(found.filter((r) => r !== undefined));
}

function outcomeText(run) {
  const o = run.dump.outcome;
  const counts =
    o.actions === undefined
      ? ""
      : `replayed ${plural(o.actions, "action")} and ${plural(o.observations, "observation")}`;
  const failure = {
    scenario: `${counts}, but the scenario failed`,
    replay: `replay failed at step ${run.failedStep + 1}`,
  }[o.stage];
  if (o.stage === "done") return `${CHECK} ${counts}`;
  return `${CROSS} ${failure || "reduction failed"}: ${o.message}`;
}

// Runs of steps over which a node's dumped field keeps one value.
function segments(run, node, field) {
  const out = [];
  for (const s of run.steps) {
    const entry =
      s.state === null ? null : nodeIn(run, run.states[s.state], node);
    const value = entry ? entry.state[field] : null;
    const last = out[out.length - 1];
    if (last && last.value === value) last.end = s.index + 1;
    else out.push({ start: s.index, end: s.index + 1, value });
  }
  return out.filter((seg) => seg.value !== null);
}

// An SVG path through the values, with gaps where they are null.
function path(values, x, y) {
  let d = "";
  values.forEach((v, k) => {
    if (v !== null)
      d += `${k && values[k - 1] !== null ? "L" : "M"}${x(k).toFixed(1)} ${y(v).toFixed(1)}`;
  });
  return d;
}

const tickKind = (s) =>
  s.kind === "retry" || s.kind === "timeout" ? s.kind : "receive";
const title = (tip) => (tip ? `<title>${esc(tip)}</title>` : "");

// A short label at a mark: right of it, or left of it near the right edge.
function markLabel(geo, x, y, text, cls, tip) {
  const flip = x + 3 + text.length * 5.4 > geo.width - 2;
  return `<text class="${cls}" x="${(flip ? x - 3 : x + 3).toFixed(1)}" y="${y}" text-anchor="${flip ? "end" : "start"}">${title(tip)}${esc(text)}</text>`;
}

// The whole run, one lane per node: its phase (band), its timeout lane (thin
// band) and its actions (ticks), then the copies in flight and the step axis.
// Each mark is labelled where it is drawn, and titled; the first lane's
// encodings are labelled in the right margin.
function renderOverview() {
  const run = ui.run;
  const svg = $("#overview");
  const n = run.steps.length;
  const width = svg.getBoundingClientRect().width || 1000;
  const geo = { left: 70, top: 25, lane: 30, width, unit: (width - 174) / n };
  geo.x = (k) => geo.left + k * geo.unit;
  geo.end = geo.x(n);
  geo.flight = geo.top + run.nodes.length * geo.lane + 1;
  geo.bottom = geo.flight + 22;
  geo.axis = geo.bottom + 10;
  geo.links = geo.axis + 12;
  geo.height = geo.links + 3;
  run.geo = n ? geo : null;
  svg.setAttribute("viewBox", `0 0 ${width} ${geo.height}`);
  svg.style.height = n ? geo.height + "px" : "0px";
  if (!n) return void (svg.innerHTML = "");
  const f = (v) => v.toFixed(1);
  const end = (x, y, text, tip, cls) =>
    `<text${cls ? ` class="${cls}"` : ""} x="${x}" y="${y}" text-anchor="end">${title(tip)}${esc(text)}</text>`;
  const p = [
    '<defs><pattern id="hatch" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="4" height="4" fill="#ecebe2"/><line x1="0" y1="0" x2="0" y2="4" stroke="#8c8a80" stroke-width="1.5"/></pattern></defs>',
  ];
  run.nodes.forEach((node, j) => {
    const y = geo.top + j * geo.lane;
    p.push(end(geo.left - 6, y + 10, node, "node " + node, "lane"));
    if (!isActive(run, node))
      p.push(
        end(
          geo.left - 6,
          y + 21,
          "inactive",
          `node ${node} takes no part, so it never acts`,
        ),
      );
    for (const [field, dy, h, what] of [
      ["phase", 1, 11, ""],
      ["timeoutState", 14, 3, "timeout lane "],
    ])
      for (const { start, end: stop, value } of segments(run, node, field)) {
        const x = geo.x(start);
        const w = (stop - start) * geo.unit;
        const tip = `node ${node} ${what}${char(value)} ${value}, steps ${start + 1}${DASH}${stop}`;
        p.push(
          `<rect class="ph-${esc(value)}" x="${f(x)}" y="${y + dy}" width="${f(w)}" height="${h}">${title(tip)}</rect>`,
        );
        const full = char(value) + " " + value;
        const label =
          w > full.length * 5 + 6 ? full : w > 10 ? char(value) : "";
        if (field === "phase" && label)
          p.push(
            `<text class="phl${value === "open" ? " dark" : ""}" x="${f(x + 3)}" y="${y + 10}">${esc(label)}</text>`,
          );
      }
    for (const kind of ["retry", "receive", "timeout"]) {
      const mine = run.steps.filter(
        (s) => s.node === node && s.kind !== "other" && tickKind(s) === kind,
      );
      const d = mine
        .map((s) => `M${f(geo.x(s.index + 0.5))} ${y + 28}v-${TICK[kind]}`)
        .join("");
      const many = kind === "retry" ? "retries" : undefined;
      const tip = `node ${node}: ${plural(mine.length, kind, many)}, one tick each`;
      if (mine.length)
        p.push(`<path class="tick-${kind}" d="${d}">${title(tip)}</path>`);
    }
  });
  // The first lane's encodings, labelled beside it.
  const kx = geo.end + 8;
  p.push(
    `<text class="key" x="${kx}" y="${geo.top + 10}">${title("band: the node's phase, darker as it advances")}${char("voting")} phase</text>`,
  );
  p.push(
    `<text class="key" x="${kx}" y="${geo.top + 19.5}">${title("thin band: the node's timeout lane")}timeout lane</text>`,
  );
  const samples = {
    retry: [char("retry"), "short tick: a retry"],
    receive: [LEFT, "middle tick: a receive, of a message from <- its sender"],
    timeout: [char("timeout"), "tall tick: a timeout"],
  };
  Object.entries(samples).forEach(([kind, [c, tip]], i) => {
    const x = kx + i * 24;
    const cls = kind === "receive" ? "key" : "key emoji";
    p.push(
      `<g>${title(tip)}<path class="tick-${kind}" d="M${f(x + 0.5)} ${geo.top + 28}v-${TICK[kind]}"/><text class="${cls}" x="${x + 3}" y="${geo.top + 28}">${esc(c)}</text></g>`,
    );
  });
  const flight = run.sparks.flight;
  const most = Math.max(1, ...flight.filter((v) => v !== null));
  const flightTip = "copies of messages in the model's network after each step";
  const d = path(
    flight,
    (k) => geo.x(k + 0.5),
    (v) => geo.flight + 19 - (v / most) * 16,
  );
  p.push(end(geo.left - 6, geo.flight + 15, "in flight", flightTip));
  p.push(`<path class="flight" d="${d}">${title(flightTip)}</path>`);
  p.push(
    `<text class="key" x="${kx}" y="${geo.flight + 6}">${title("the most copies in flight after any step")}max ${most}</text>`,
  );
  p.push(end(geo.left - 6, geo.axis, "step", "steps, in replay order"));
  const tick = niceTick(n, geo.end - geo.left);
  for (let k = tick; k <= n; k += tick)
    p.push(
      `<text x="${f(geo.x(k - 0.5))}" y="${geo.axis}" text-anchor="middle">${k}</text>`,
    );
  const skipped = run.steps.findIndex((s) => s.status === "skipped");
  if (skipped >= 0) {
    const x = geo.x(skipped);
    const tip =
      run.failedStep >= 0
        ? `not replayed: the replay stopped at step ${run.failedStep + 1}`
        : "not replayed";
    p.push(
      `<rect class="skipped-region" x="${f(x)}" y="${geo.top}" width="${f(geo.end - x)}" height="${geo.bottom - geo.top}">${title(tip)}</rect>`,
    );
    if (geo.end - x > 160)
      p.push(end(f(geo.end), 9, "not replayed", tip, "mark note"));
  }
  if (run.failedStep >= 0) {
    const x = geo.x(run.failedStep + 0.5);
    const tip = `the replay failed at step ${run.failedStep + 1}: ${run.dump.outcome.message}`;
    p.push(
      `<line class="failmark" x1="${f(x)}" x2="${f(x)}" y1="11" y2="${geo.bottom}">${title(tip)}</line>`,
    );
    p.push(markLabel(geo, x, 9, CROSS + " failed here", "mark bad", tip));
  }
  if (run.dump.outcome.stage === "scenario") {
    const tip =
      "after the last step, the scenario failed: " + run.dump.outcome.message;
    p.push(end(f(geo.end), 9, CROSS + " scenario failed", tip, "mark bad"));
  }
  p.push(
    '<g id="links"></g>',
    `<g id="cursor">${title("the selected step")}<line class="cursor" y1="21" y2="${geo.bottom}"/><rect class="labelbg" y="11" height="11"/><text class="mark" y="20"></text></g>`,
  );
  svg.innerHTML = p.join("");
}

function niceTick(count, width) {
  const target = Math.max(1, (count * 46) / Math.max(width, 1));
  return (
    [1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000].find(
      (t) => t >= target,
    ) || 1000
  );
}

function updateCursor() {
  const geo = ui.run && ui.run.geo;
  const group = $("#cursor");
  if (!geo || !group || ui.step < 0) return;
  const x = geo.x(ui.step + 0.5);
  const text = "step " + (ui.step + 1);
  const w = text.length * 5.6 + 4;
  const flip = x + 3 + w > geo.width - 2;
  const [, line, background, label] = group.children;
  const set = (e, attrs) =>
    Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
  set(line, { x1: x.toFixed(1), x2: x.toFixed(1) });
  set(label, {
    x: (flip ? x - 3 : x + 3).toFixed(1),
    "text-anchor": flip ? "end" : "start",
  });
  set(background, {
    x: (flip ? x - 3 - w : x + 1).toFixed(1),
    width: w.toFixed(1),
  });
  label.textContent = text;
}

// Marks the steps linked to a hovered one, each labelled with how: the send
// that a hovered receive took, or the receives that took a hovered retry's
// sends. Nearby marks with the same label share it.
function markLinks(marks) {
  const geo = ui.run && ui.run.geo;
  const group = $("#links");
  if (!group || !geo) return;
  const parts = [];
  const clusters = [];
  for (const m of [...marks].sort((a, b) => a.step - b.step)) {
    const x = geo.x(m.step + 0.5);
    parts.push(
      `<line class="linkmark" x1="${x.toFixed(1)}" x2="${x.toFixed(1)}" y1="${geo.top}" y2="${geo.links - 9}">${title(m.title)}</line>`,
    );
    const last = clusters[clusters.length - 1];
    if (last && last.label === m.label && x - last.x < 64)
      last.titles.push(m.title);
    else clusters.push({ x, label: m.label, titles: [m.title] });
  }
  for (const { x, label, titles } of clusters) {
    const text = label + (titles.length > 1 ? " \u00D7" + titles.length : "");
    parts.push(
      markLabel(geo, x, geo.links, text, "mark link", titles.join("\n")),
    );
  }
  group.innerHTML = parts.join("");
}

// What the overview shows under the pointer, at step k and height y.
function overviewTip(run, k, y) {
  const geo = run.geo;
  const s = run.steps[k];
  const at = `step ${k + 1}: `;
  const what = `node ${s.node} ${plain(stepHtml(run, s))}`;
  const node = run.nodes[Math.floor((y - geo.top) / geo.lane)];
  if (y >= geo.top && y < geo.flight && node !== undefined) {
    const sub = (y - geo.top) % geo.lane;
    const entry =
      s.state === null ? null : nodeIn(run, run.states[s.state], node);
    if (!entry) return at + "not replayed";
    const { phase, timeoutState: lane } = entry.state;
    if (sub < 13)
      return at + `node ${node} is in phase ${char(phase)} ${phase}`;
    if (sub < 19)
      return at + `node ${node}'s timeout lane is ${char(lane)} ${lane}`;
    return node === s.node ? at + what : at + what + `; node ${node} waits`;
  }
  if (y < geo.flight || y >= geo.bottom) return at + what;
  const v = run.sparks.flight[k];
  return (
    at +
    (v === null
      ? "not replayed"
      : plural(v, "copy", "copies") + " of messages in flight")
  );
}

// A step in its node's lane: its action, what changed in that node's dumped
// state, and the dumped notifications.
function stepHtml(run, s) {
  const x = s.action === undefined ? null : run.ins[s.action];
  if (!x) return esc(s.status);
  const a = x.action;
  const observed = s.ins
    .map((i) => run.ins[i])
    .find((y) => y.kind === "outputs");
  const sent = x.outputs ? x.outputs.sent : observed ? observed.sent : [];
  const parts = [
    a.kind === "retry"
      ? `${glyph("retry")} ${sentHtml(sent, s.node)}`
      : a.kind === "timeout"
        ? `${glyph("timeout")} timeout`
        : route(a.message, a.target, LEFT, a.source, a.txid),
  ];
  const before = nodeIn(run, run.states[s.prev], s.node);
  const after =
    s.state === null ? null : nodeIn(run, run.states[s.state], s.node);
  if (before && after) {
    const { phase, timeoutState: lane } = after.state;
    if (before.state.phase !== phase)
      parts.push(
        `<span class="chg" title="phase changed to ${esc(phase)}">${RIGHT}${phaseHtml(phase)}</span>`,
      );
    if (before.state.timeoutState !== lane)
      parts.push(
        `<span class="note" title="timeout lane changed to ${esc(lane)}" data-text="${esc(`timeout lane${RIGHT}${char(lane)} ${lane}`)}">${glyph("timeout", "timeout lane")}${RIGHT}${glyph(lane)}</span>`,
      );
  }
  for (const note of x.outputs ? x.outputs.notifications : [])
    parts.push(noteHtml(note));
  return parts.join(" ");
}

function renderTrace() {
  for (const tab of document.querySelectorAll(".tabs .tab"))
    tab.classList.toggle("cur", tab.dataset.mode === ui.mode);
  const run = ui.run;
  const rows = $("#rows");
  run.rowOf = [];
  run.recordRow = new Map();
  if (ui.mode === "log") {
    if (!run.records.length)
      return void (rows.innerHTML = `<p class="empty">The replayer read no records: ${esc(run.dump.outcome.message)}</p>`);
    const failing = failingRecords(run);
    const body = run.files.map((file) => [
      `<tr class="file"><td colspan="4" title="${esc(file)}">${esc(run.shortName.get(file))}</td></tr>`,
      ...run.records.map((r, i) => {
        if (r.file !== file) return "";
        const step = run.stepOfRecord.get(i);
        const s = step === undefined ? null : run.steps[step];
        const cls =
          (failing.has(i) ? "failed" : s ? s.status : "unreplayed") +
          (s && !visible(s) ? " hidden" : "");
        const where = s
          ? "replayed in step " + (step + 1)
          : "in no replayed step";
        return `<tr data-record="${i}" class="${cls}"><td class="num" title="${where}">${s ? step + 1 : ""}</td><td class="num">${r.line}</td><td>${esc(r.value.node)}:${esc(r.value.sequence)}</td><td title="${esc(JSON.stringify(r.value))}">${recordHtml(r.value)}</td></tr>`;
      }),
    ]);
    rows.innerHTML = `<table class="lanes"><thead><tr><th class="num">step</th><th class="num">line</th><th class="seq">node:seq</th><th>record</th></tr></thead><tbody>${body.flat().join("")}</tbody></table>`;
    for (const tr of rows.querySelectorAll("tbody tr[data-record]"))
      run.recordRow.set(Number(tr.dataset.record), tr);
    return;
  }
  if (!run.steps.length)
    return void (rows.innerHTML = `<p class="empty">Nothing was replayed. The log order shows the records that the replayer read.</p>`);
  const inactive = ' <span class="note">inactive</span>';
  const head = run.nodes.map(
    (node) => `<th>${esc(node)}${isActive(run, node) ? "" : inactive}</th>`,
  );
  const cols = run.nodes.map((node) =>
    isActive(run, node) ? "<col>" : '<col class="narrow">',
  );
  const body = run.steps.map((s) => {
    const html = stepHtml(run, s);
    const cells = run.nodes.map((node) =>
      node === s.node
        ? `<td title="${esc(plain(html))}">${html}</td>`
        : "<td></td>",
    );
    const mark = s.status === "failed" ? glyph("failed") + " " : "";
    return `<tr data-step="${s.index}" class="${s.status}${visible(s) ? "" : " hidden"}"><td class="num">${mark}${s.index + 1}</td>${cells.join("")}</tr>`;
  });
  rows.innerHTML = `<table class="lanes"><colgroup><col class="numcol">${cols.join("")}</colgroup><thead><tr><th class="num">step</th>${head.join("")}</tr></thead><tbody>${body.join("")}</tbody></table>`;
  run.rowOf = [...rows.querySelectorAll("tbody tr")];
}

// Highlights the selected step's rows, and scrolls the first into view.
function markSelection() {
  const run = ui.run;
  for (const tr of document.querySelectorAll("#rows tr.sel"))
    tr.classList.remove("sel");
  if (ui.step < 0) return;
  const rows =
    ui.mode === "steps"
      ? [run.rowOf[ui.step]]
      : run.steps[ui.step].records.map((r) => run.recordRow.get(r));
  const found = rows.filter((tr) => tr !== undefined);
  found.forEach((tr) => tr.classList.add("sel"));
  if (found.length) found[0].scrollIntoView({ block: "nearest" });
}

// Rows and overview marks linked to a hovered row, from the dumped `consumed`
// links: the send that a receive took, or the receives that took a send.
function linksOf(run, element) {
  const tr = element.closest("tr");
  const sender = (from, to) => ({
    step: from,
    label: "send taken",
    title: `step ${from + 1} queued the copy that step ${to + 1} took`,
  });
  const taker = (to, from) => ({
    step: to,
    label: "taken by",
    title: `step ${to + 1} took a copy that step ${from + 1} queued`,
  });
  if (tr && tr.dataset.step !== undefined) {
    const s = run.steps[Number(tr.dataset.step)];
    const takers = (s.to || []).filter((t) => t !== undefined);
    const marks = [
      ...(s.from === undefined ? [] : [sender(s.from, s.index)]),
      ...takers.map((t) => taker(t, s.index)),
    ];
    return { rows: marks.map((m) => run.rowOf[m.step]), marks };
  }
  if (!tr || tr.dataset.record === undefined) return { rows: [], marks: [] };
  const r = Number(tr.dataset.record);
  const step = run.stepOfRecord.get(r);
  const taken = run.takerOfRecord.get(r);
  const s = step === undefined ? null : run.steps[step];
  const records = [];
  const marks = [];
  if (taken !== undefined) {
    marks.push(taker(taken, step));
    records.push(...run.steps[taken].records);
  }
  if (s && s.fromRecord !== undefined) {
    marks.push(sender(s.from, s.index));
    records.push(s.fromRecord);
  }
  return { rows: records.map((k) => run.recordRow.get(k)), marks };
}

function sparkline(values, index, tip) {
  const most = Math.max(1, ...values.filter((v) => v !== null));
  const x = (k) =>
    1 + (values.length <= 1 ? 0 : (k / (values.length - 1)) * 68);
  const y = (v) => 11 - (v / most) * 10;
  const v = values[index];
  const dot =
    v === null || v === undefined
      ? ""
      : `<circle cx="${x(index).toFixed(1)}" cy="${y(v).toFixed(1)}" r="1.7"/>`;
  return `<svg class="spark" width="70" height="12" viewBox="0 0 70 12">${title(tip)}<path d="${path(values, x, y)}"/>${dot}</svg>`;
}

// One column per node: the dumped node state, with what changed since the
// previous dumped state highlighted, and the dumped enabled local actions.
function nodesHtml(run, s, cur, prev) {
  const head = run.nodes.map((node) =>
    node === s.node
      ? `<th class="actor" title="node ${esc(node)} acts in this step">${esc(node)} ${glyph(s.kind)}</th>`
      : cur.active.includes(node)
        ? `<th>${esc(node)}</th>`
        : `<th class="inactive" title="node ${esc(node)} takes no part">${esc(node)} <span class="note">inactive</span></th>`,
  );
  const row = (label, cell) =>
    `<tr><th>${label}</th>${run.nodes.map((node, j) => cell(nodeIn(run, cur, node), nodeIn(run, prev, node), j)).join("")}</tr>`;
  const scalar = (label, key, render) =>
    row(
      label,
      (c, p) =>
        `<td class="${p && !same(p.state[key], c.state[key]) ? "chg" : ""}">${render(c.state[key])}</td>`,
    );
  const items = (label, key, item) =>
    row(label, (c, p, j) => {
      const was = new Set(
        (p ? p.state[key] : []).map((e) => JSON.stringify(e)),
      );
      const entries = c.state[key].map((e) =>
        was.has(JSON.stringify(e))
          ? esc(item(e))
          : `<span class="chg cell">${esc(item(e))}</span>`,
      );
      const tip = `node ${run.nodes[j]}'s ${label} over the whole run; the dot marks this step`;
      return `<td>${c.state[key].length}${sparkline(run.sparks[key][j], s.index, tip)}<br>${entries.join(" ")}</td>`;
    });
  const enabled = (c, p, j) =>
    ["retry", "timeout"].map((key) => {
      const tip = `${key} is ${c[key] ? "" : "not "}enabled for node ${run.nodes[j]} in this state`;
      return `<span class="${c[key] ? "" : "off"}" title="${esc(tip)}">${glyph(key)} ${key}</span>`;
    });
  const restart = (v) =>
    v ? glyph("restart", "the node requested a restart") + " requested" : DASH;
  return [
    `<table class="nodes"><thead><tr><th></th>${head.join("")}</tr></thead><tbody>`,
    scalar("phase", "phase", phaseHtml),
    scalar("timeout lane", "timeoutState", phaseHtml),
    scalar("chosen", "chosen", (v) => esc(v ?? DASH)),
    scalar("open kind", "openKind", (v) => esc(v ?? DASH)),
    scalar("restart", "restartRequested", restart),
    items("gossips", "gossips", (e) => e[0] + ":" + e[1]),
    items("votes", "votes", (e) => e),
    row("enabled", (c, p, j) => `<td>${enabled(c, p, j).join(" ")}</td>`),
    "</tbody></table>",
  ].join("");
}

// The network's dumped copies, one source-by-target matrix per message, with
// the change since the previous dumped state as a superscript.
function networkHtml(run, cur, prev) {
  if (!run.messageKeys.length) return '<p class="note">nothing sent</p>';
  const id = (key, source, target) => `${key}|${source}|${target}`;
  const index = (st) =>
    new Map(
      st.network.map((e) => [
        id(messageKey(e.envelope), e.envelope.source, e.envelope.target),
        e,
      ]),
    );
  const [now, then] = [index(cur), index(prev)];
  const total = cur.network.reduce((sum, e) => sum + e.count, 0);
  const stuck = cur.network.reduce(
    (sum, e) => sum + (e.deliverable ? 0 : e.count),
    0,
  );
  const cell = (key, source, target) => {
    const e = now.get(id(key, source, target));
    const was = then.get(id(key, source, target));
    const count = e ? e.count : 0;
    const delta = count - (was ? was.count : 0);
    const cls = (e && !e.deliverable ? "dead" : "") + (delta ? " chg" : "");
    const sup = delta
      ? `<sup>${delta > 0 ? "+" + delta : "\u2212" + -delta}</sup>`
      : "";
    const senders = e ? e.sentBy.map((i) => run.stepOf[i] + 1) : [];
    const listed =
      senders.slice(0, 16).join(", ") + (senders.length > 16 ? "\u2026" : "");
    const tip = e
      ? `${plain(sendHtml(e.envelope, source))}: ${plural(count, "copy", "copies")}, queued by steps ${listed}; ${e.deliverable ? "deliverable" : "not deliverable"}`
      : "";
    return `<td class="${cls}" title="${esc(tip)}">${count || (delta ? "0" : "")}${sup}</td>`;
  };
  const matrices = run.messageKeys.map((key) => {
    const rows = run.nodes.map(
      (s) =>
        `<tr><th>${esc(s)}</th>${run.nodes.map((t) => cell(key, s, t)).join("")}</tr>`,
    );
    return `<table class="matrix"><caption>${glyph(key.split(" ")[0])} ${esc(key)}</caption><tr><th class="note">from${DOT}to</th>${run.nodes.map((t) => `<th>${esc(t)}</th>`).join("")}</tr>${rows.join("")}</table>`;
  });
  const keys = [
    `${plural(total, "copy", "copies")} in flight`,
    "rows: from, columns: to",
    '<sup class="chg">+1</sup> changed in this step',
    ...(stuck ? [`<i>italics</i>: ${stuck} not deliverable`] : []),
  ];
  return `<div class="note">${keys.join(` ${DOT} `)}</div><div class="matrices">${matrices.join("")}</div>`;
}

const stepLink = (k) => `<a data-goto="${k}">step ${k + 1}</a>`;

function instructionHtml(run, s, x) {
  const fields = (f) =>
    Object.entries(f)
      .map(([k, v]) => esc(k + "=") + valueHtml(k, v))
      .join(" ");
  let html;
  if (x.kind === "state") html = esc(`state of ${x.node}: `) + fields(x.fields);
  else if (x.kind === "outputs")
    html = `${esc(`outputs of ${x.node}: sent `)}${list(x.sent, (m) => sendHtml(m, x.node))}, notified ${list(x.notifications, noteHtml)}`;
  else {
    const a = x.action;
    html =
      a.kind === "deliver"
        ? `deliver ${route(a.message, a.target, LEFT, a.source, a.txid)}`
        : `${glyph(a.kind)} ${esc(a.kind + " on " + a.node)}`;
    if (x.status === "ok") html += " (enabled)";
    const c = x.consumed;
    if (c)
      html += `<br>took the copy that ${stepLink(run.stepOf[c.sentBy])} queued, its send ${c.position + 1}${c.record ? `, logged at ${esc(originText(run, c.record))}` : ""}`;
    if (x.outputs && x.outputs.sent.length) {
      const fate = (t) =>
        t === undefined
          ? '<span class="note">not taken</span>'
          : "taken by " + stepLink(t);
      html +=
        "<br>" +
        x.outputs.sent
          .map(
            (m, k) =>
              `${sendHtml(m, s.node)} ${fate(s.to ? s.to[k] : undefined)}`,
          )
          .join("; ");
    }
  }
  if (x.status !== "failed") return html;
  const checks = (x.checks || []).map(
    (c) =>
      `<tr class="${c.error ? "bad" : ""}"><td>${c.error ? glyph("failed", "the observed value differs from the model's") : glyph("ok", "the observed value matches the model's")}</td><td>${esc(c.key)}</td><td>${valueHtml(c.key, c.observed, x.node)}</td><td>${valueHtml(c.key, c.model, x.model ? x.model.node : x.node)}</td></tr>`,
  );
  const guards = Object.entries(x.guards || {}).map(
    ([key, on]) =>
      `<span class="${on ? "" : "bad"}">${on ? glyph("ok", "this guard of the model's step holds") : glyph("failed", "this guard of the model's step fails")} ${esc(GUARDS[key] || key)}</span>`,
  );
  if (x.checks)
    html += `<table class="checks"><tr><th></th><th>field</th><th>observed</th><th>model</th></tr>${checks.join("")}</table>`;
  if (x.guards) html += `<div class="guards">${guards.join("")}</div>`;
  return html + `<div class="error">${esc(x.error)}</div>`;
}

function describeStep(run, s) {
  const a = s.action === undefined ? null : run.ins[s.action].action;
  const node = "node " + s.node;
  if (!a) return node;
  return (
    { retry: `${node} retries`, timeout: `${node} times out` }[a.kind] ||
    `${node} receives ${a.message} from ${a.source}`
  );
}

// JSON with 2-space indentation, as HTML. Arrays of scalars that fit stay on
// one line, so expected_locations reads ["0", "1", "2"].
function prettyJson(value, indent = "") {
  const inner = indent + "  ";
  if (Array.isArray(value)) {
    const line = "[" + value.map((v) => JSON.stringify(v)).join(", ") + "]";
    if (
      value.every((v) => v === null || typeof v !== "object") &&
      line.length <= 60
    )
      return esc(line);
    return `[\n${value.map((v) => inner + prettyJson(v, inner)).join(",\n")}\n${indent}]`;
  }
  if (value === null || typeof value !== "object")
    return esc(JSON.stringify(value));
  const entries = Object.entries(value).map(
    ([k, v]) =>
      `${inner}<span class="jk">${esc(JSON.stringify(k))}</span>: ${prettyJson(v, inner)}`,
  );
  return entries.length ? `{\n${entries.join(",\n")}\n${indent}}` : "{}";
}

// Records as compact lines that open to pretty-printed JSON. Those in `open`
// start open, unless opened or closed by hand.
function recordsHtml(run, records, open) {
  const record = (r) => {
    const rec = run.records[r];
    const shown = ui.recordOpen.has(r) ? ui.recordOpen.get(r) : open.has(r);
    return `<details data-record-details="${r}"${shown ? " open" : ""}><summary><a data-record="${r}" title="${esc(rec.file)}: show in log order">${esc(originText(run, rec))}</a> <span class="compact">${esc(JSON.stringify(rec.value))}</span></summary><pre class="json">${prettyJson(rec.value)}</pre></details>`;
  };
  return `<div class="records">${records.map(record).join("")}</div>`;
}

function renderState() {
  const run = ui.run;
  const pane = $("#state");
  if (!run.steps.length) {
    const failing = [...failingRecords(run)];
    const none =
      '<p class="note">No step was replayed, so there is no model state to show.</p>';
    const named =
      "<h2>named records</h2>" + recordsHtml(run, failing, new Set(failing));
    return void (pane.innerHTML = `<div class="banner">${esc(outcomeText(run))}</div>${failing.length ? named : none}`);
  }
  const s = run.steps[ui.step];
  const [cur, prev] = [
    run.states[s.state === null ? s.prev : s.state],
    run.states[s.prev],
  ];
  const status =
    { ok: "replayed", failed: "failed" }[s.status] || "not replayed";
  const parts = [
    `<div class="headline"><b>Step ${s.index + 1}</b> of ${run.steps.length} ${DOT} ${esc(describeStep(run, s))} ${DOT} <span class="${s.status === "ok" ? "" : "chg"}">${status}</span></div>`,
  ];
  if (s.status === "skipped")
    parts.push(
      `<div class="banner">The replay stopped at ${stepLink(run.failedStep)}; this shows the state it stopped in.</div>`,
    );
  if (s.index === run.steps.length - 1 && run.dump.outcome.stage === "scenario")
    parts.push(`<div class="banner">${esc(outcomeText(run))}</div>`);
  const changed =
    s.state === null
      ? ""
      : '<span class="key"><span class="chg cell">highlighted</span>: changed in this step</span>';
  parts.push(
    `<h2>model state ${s.state === null ? "when the replay stopped" : "after this step"}${changed}</h2>`,
    nodesHtml(run, s, cur, prev),
  );
  parts.push(
    "<h2>messages in flight</h2>",
    networkHtml(run, cur, prev),
    "<h2>instructions of this step</h2>",
  );
  const instruction = (i) => {
    const x = run.ins[i];
    const rule = x.origins.length ? x.origins[0].rule : "";
    return `<tr class="${x.status}"><td>${glyph(x.status)}</td><td class="note" title="instruction ${i + 1}, as the replayer numbers it">${i + 1}</td><td class="note" title="the reduction rule that placed it">${esc(rule)}</td><td>${instructionHtml(run, s, x)}</td></tr>`;
  };
  parts.push(`<table class="ins">${s.ins.map(instruction).join("")}</table>`);
  // The step's first record, any the failure names, and a clicked one open.
  const open = s.records.includes(ui.focusRecord)
    ? new Set()
    : new Set([s.records[0], ...failingRecords(run)]);
  open.add(ui.focusRecord);
  parts.push(
    '<h2>records<span class="key">click a line to open or close it</span></h2>',
    recordsHtml(run, s.records, open),
  );
  pane.innerHTML = parts.join("");
}

function renderHeader() {
  const { meta, dump, nodes, steps, failedStep } = ui.run;
  const outcome = $("#outcome");
  outcome.className = dump.outcome.ok ? "ok" : "bad";
  outcome.textContent = outcome.title = outcomeText(ui.run);
  const [kind, verb] = meta.valid ? ["valid", "accept"] : ["invalid", "reject"];
  $("#change").textContent = meta.change
    ? `${kind} trace of ${meta.base}, which the replayer must ${verb}: ${meta.change}`
    : "";
  $("#fail").disabled = failedStep < 0 && dump.outcome.stage !== "scenario";
  const toggle = (hide, tip, html) =>
    `<span class="tog" data-hide="${esc(hide)}" title="${esc(tip)}">${html}</span>`;
  $("#nodes").innerHTML =
    '<span class="sc">nodes</span> ' +
    nodes
      .map((n) => toggle("node " + n, `show or hide node ${n}'s steps`, esc(n)))
      .join("");
  const kinds = KINDS.filter((k) => steps.some((s) => s.kind === k));
  $("#kinds").innerHTML =
    '<span class="sc">kinds</span> ' +
    kinds
      .map((k) =>
        toggle("kind " + k, `show or hide ${k} steps`, `${glyph(k)} ${k}`),
      )
      .join("");
}

function select(k) {
  const run = ui.run;
  ui.step = run.steps.length ? clamp(k, 0, run.steps.length - 1) : -1;
  markSelection();
  updateCursor();
  renderState();
  const shown = run.steps.filter(visible).length;
  const filtered = shown < run.steps.length ? ` (${shown} shown)` : "";
  $("#counter").textContent = run.steps.length
    ? `step ${ui.step + 1} / ${run.steps.length}${filtered}`
    : "no steps";
  for (const t of document.querySelectorAll("[data-hide]"))
    t.classList.toggle("off", ui.hidden.has(t.dataset.hide));
  const hash = `#run=${encodeURIComponent(run.meta.id)}${ui.step >= 0 ? "&step=" + (ui.step + 1) : ""}`;
  if (location.hash !== hash) history.replaceState(null, "", hash);
}

// Moves by `delta` steps among those that the filters show.
function move(delta) {
  const steps = ui.run.steps;
  let k = ui.step;
  for (
    let j = k + Math.sign(delta), left = Math.abs(delta);
    left && j >= 0 && j < steps.length;
    j += Math.sign(delta)
  )
    if (visible(steps[j])) [k, left] = [j, left - 1];
  select(k);
}

function edge(last) {
  const s = (last ? [...ui.run.steps].reverse() : ui.run.steps).find(visible);
  if (s) select(s.index);
}

function toFailure() {
  const run = ui.run;
  if (run.failedStep >= 0) select(run.failedStep);
  else if (run.dump.outcome.stage === "scenario") select(run.steps.length - 1);
}

function setMode(mode) {
  ui.mode = mode;
  renderTrace();
  markSelection();
}

function show(meta, dump, stepNumber) {
  const run = (ui.run = prepare(meta, dump));
  ui.hidden.clear();
  ui.recordOpen.clear();
  ui.focusRecord = -1;
  ui.mode = run.steps.length ? "steps" : "log";
  $("#run").value = meta.id;
  renderHeader();
  renderOverview();
  renderTrace();
  const ending =
    run.dump.outcome.stage === "scenario" ? run.steps.length - 1 : 0;
  select(
    stepNumber ? stepNumber - 1 : run.failedStep >= 0 ? run.failedStep : ending,
  );
  const named = [...failingRecords(run)].map((r) => run.recordRow.get(r));
  if (!run.steps.length && named[0])
    named[0].scrollIntoView({ block: "center" });
}

async function openRun(id, stepNumber) {
  const meta = ui.runs.find((r) => r.id === id);
  if (!meta) return;
  if (!ui.cache.has(id))
    ui.cache.set(
      id,
      await (await fetch("data/" + encodeURIComponent(meta.dump))).json(),
    );
  show(meta, ui.cache.get(id), stepNumber);
}

function renderRunPicker() {
  const option = (r) =>
    `<option value="${esc(r.id)}">${esc(r.title)} ${r.exitCode === 0 ? CHECK : CROSS}</option>`;
  const group = (label, runs) =>
    runs.length
      ? `<optgroup label="${label}">${runs.map(option).join("")}</optgroup>`
      : "";
  $("#run").innerHTML =
    group(
      "logs",
      ui.runs.filter((r) => !r.base),
    ) +
    group(
      "invalid traces",
      ui.runs.filter((r) => r.base && !r.valid),
    ) +
    group(
      "valid traces",
      ui.runs.filter((r) => r.base && r.valid),
    );
}

function parseHash() {
  const params = new URLSearchParams(location.hash.slice(1));
  return { run: params.get("run"), step: Number(params.get("step")) || 0 };
}

const ACTIONS = {
  first: () => edge(false),
  prev: () => move(-1),
  next: () => move(1),
  last: () => edge(true),
  fail: toFailure,
};
const KEYS = {
  ArrowRight: 1,
  ArrowDown: 1,
  j: 1,
  J: 1,
  ArrowLeft: -1,
  ArrowUp: -1,
  k: -1,
  K: -1,
};
const MORE_KEYS = {
  PageDown: () => move(10),
  PageUp: () => move(-10),
  Home: () => edge(false),
  End: () => edge(true),
  f: toFailure,
  l: () => setMode(ui.mode === "steps" ? "log" : "steps"),
};

// Clicks on any data-* control, a record link or summary, or a row.
function click(e) {
  const el = e.target.closest(
    "[data-act], [data-hide], [data-mode], [data-goto], a[data-record], .records summary, #rows tbody tr",
  );
  if (!el || !ui.run) return;
  const { act, hide, mode, goto, record, step } = el.dataset;
  const details = el.parentElement;
  if (act) ACTIONS[act]();
  else if (hide) {
    if (!ui.hidden.delete(hide)) ui.hidden.add(hide);
    setMode(ui.mode);
    select(ui.step);
  } else if (mode) setMode(mode);
  else if (goto) select(Number(goto));
  else if (el.tagName === "SUMMARY")
    ui.recordOpen.set(Number(details.dataset.recordDetails), !details.open);
  else if (record !== undefined) {
    ui.focusRecord = Number(record);
    const target = ui.run.stepOfRecord.get(ui.focusRecord);
    if (el.tagName === "A") {
      e.preventDefault();
      if (ui.mode !== "log") setMode("log");
    }
    if (target !== undefined) select(target);
    const tr = ui.run.recordRow.get(ui.focusRecord);
    if (el.tagName === "A" && tr) tr.scrollIntoView({ block: "center" });
  } else if (step !== undefined) select(Number(step));
}

function wire() {
  document.addEventListener("click", click);
  document.addEventListener("change", async (e) => {
    if (e.target.id === "run") return openRun(e.target.value);
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const dump = JSON.parse(await file.text());
    const meta = {
      id: file.name,
      title: file.name,
      dump: file.name,
      exitCode: dump.outcome.ok ? 0 : 1,
    };
    ui.runs = ui.runs.filter((r) => r.id !== meta.id).concat([meta]);
    ui.cache.set(meta.id, dump);
    renderRunPicker();
    show(meta, dump);
  });
  document.addEventListener("keydown", (e) => {
    if (!ui.run || e.ctrlKey || e.metaKey || e.altKey) return;
    if (["SELECT", "INPUT", "TEXTAREA"].includes(e.target.tagName)) return;
    if (KEYS[e.key]) move(KEYS[e.key] * (e.shiftKey ? 10 : 1));
    else if (MORE_KEYS[e.key]) MORE_KEYS[e.key]();
    else return;
    e.preventDefault();
  });
  let linked = [];
  const unlink = () => {
    linked.forEach((tr) => tr.classList.remove("linked"));
    linked = [];
    markLinks([]);
  };
  const rows = $("#rows");
  rows.addEventListener("mouseover", (e) => {
    unlink();
    if (!ui.run) return;
    const links = linksOf(ui.run, e.target);
    linked = links.rows.filter((tr) => tr !== undefined);
    linked.forEach((tr) => tr.classList.add("linked"));
    markLinks(links.marks);
  });
  rows.addEventListener("mouseleave", unlink);
  const svg = $("#overview");
  const tip = $("#tip");
  const at = (e) => {
    const geo = ui.run && ui.run.geo;
    const box = svg.getBoundingClientRect();
    const x = ((e.clientX - box.left) * (geo ? geo.width : 0)) / box.width;
    const y = ((e.clientY - box.top) * (geo ? geo.height : 0)) / box.height;
    return geo
      ? [
          clamp(
            Math.floor((x - geo.left) / geo.unit),
            0,
            ui.run.steps.length - 1,
          ),
          y,
        ]
      : [-1];
  };
  svg.addEventListener("pointerdown", (e) => {
    const [k] = at(e);
    if (k < 0) return;
    ui.dragging = true;
    svg.setPointerCapture(e.pointerId);
    select(k);
  });
  svg.addEventListener("pointermove", (e) => {
    const [k, y] = at(e);
    if (k < 0) return;
    if (ui.dragging && k !== ui.step) select(k);
    tip.textContent = overviewTip(ui.run, k, y);
    tip.style.display = "block";
    tip.style.left =
      Math.min(e.clientX + 12, window.innerWidth - tip.offsetWidth - 4) + "px";
    tip.style.top = e.clientY - 30 + "px";
  });
  svg.addEventListener("pointerup", () => (ui.dragging = false));
  svg.addEventListener("pointerleave", () => (tip.style.display = "none"));
  window.addEventListener("hashchange", () => {
    const hash = parseHash();
    if (!ui.run || hash.run !== ui.run.meta.id) openRun(hash.run, hash.step);
    else if (hash.step) select(hash.step - 1);
  });
  window.addEventListener("resize", () => {
    if (!ui.run) return;
    renderOverview();
    updateCursor();
  });
}

async function boot() {
  wire();
  ui.runs = await fetch("data/index.json")
    .then((response) => response.json())
    .catch(() => []);
  renderRunPicker();
  const hash = parseHash();
  const first = ui.runs.length ? ui.runs[0].id : null;
  const id = ui.runs.some((r) => r.id === hash.run) ? hash.run : first;
  if (id) await openRun(id, hash.step);
  else
    $("#rows").innerHTML =
      '<p class="empty">No runs found in data/. Run build.py, or open a dump written by --dump.</p>';
}

boot();
