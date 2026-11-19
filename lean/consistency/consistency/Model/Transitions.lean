module

public import consistency.Model.History

@[expose] public section

namespace consistency.Model

/-- Extend the externally visible history by one event. -/
def appendEvent (state : State) (event : Event) : State :=
  { state with history := state.history ++ [event] }

/-- Extend a branch after the caller has checked its one-based index. -/
def appendEntry (state : State) (branch : Nat) (entry : Entry) : State :=
  { state with branches := state.branches.modify (branch - 1) (· ++ [entry]) }

/-- Branches eligible for election retain all known committed entries. -/
def hasCommittedPrefix (state : State) (branch : List Entry) : Bool :=
  let frontier := commitSeqno state.history
  frontier ≤ branch.length
  && (frontier = 0
      || (match at? branch frontier with
          | some entry =>
              (statusIDs state.history .committed).contains ⟨entry.view, frontier⟩
          | none => false))

/-- A transaction can be declared invalid under three alternatives.
The commit frontier has passed this position with a different transaction, or a
higher view has committed below this position, or the current-view suffix is
declared invalid before the frontier reaches it.
The last alternative permits invalid reports before commit knowledge catches up;
`commit` must correspondingly exclude that suffix. -/
def mayInvalidate (state : State) (txid : TxID) : Bool :=
  let frontier := commitSeqno state.history
  match state.branches.getLast? with
  | none => false
  | some latest =>
      (frontier ≥ txid.seqno
        && (match at? latest txid.seqno with
            | some entry => entry.view != txid.view
            | none => false))
      || (frontier > 0
          && frontier < txid.seqno
          && (match at? latest frontier with
              | some entry => entry.view > txid.view
              | none => false))
      || (txid.view = state.branches.length && txid.seqno > frontier)

/-- Submit a transaction request with the next shared request ID. -/
def request (state : State) (kind : TxType) : Option State :=
  some (appendEvent state (.request kind (nextRequestId state.history)))

/-- Execute a previously unexecuted write on an eligible branch.
Any eligible branch may be selected, not just the newest: the request can be
picked up by the current leader or a former leader. -/
def execute (state : State) (requestIndex branch : Nat) : Option State := do
  let .request .rw tx ← at? state.history requestIndex | none
  guard (activeBranch state branch)
  guard (!(state.branches.any fun ledger => ledger.any fun entry => entry.tx == some tx))
  return appendEntry state branch ⟨branch, some tx⟩

/-- Respond to an executed write with its observed prefix and transaction ID. -/
def respond (state : State) (requestIndex branch seqno : Nat) : Option State := do
  let .request .rw tx ← at? state.history requestIndex | none
  guard (!responded state.history requestIndex .rw tx)
  guard (activeBranch state branch)
  let ledger ← at? state.branches branch
  let entry ← at? ledger seqno
  guard (entry.tx == some tx)
  return appendEvent state
    (.response .rw tx (writes (ledger.take seqno)) ⟨entry.view, seqno⟩)

/-- Execute and respond to a read-only request on a nonempty eligible branch.
Reads are always forwarded; unlike writes, execution and response are one action. -/
def read (state : State) (requestIndex branch : Nat) : Option State := do
  let .request .ro tx ← at? state.history requestIndex | none
  guard (!responded state.history requestIndex .ro tx)
  guard (activeBranch state branch)
  let ledger ← at? state.branches branch
  let entry ← ledger.getLast?
  return appendEvent state (.response .ro tx (writes ledger) ⟨entry.view, ledger.length⟩)

/-- Report commitment when the newest branch and prior invalid statuses permit it. -/
def commit (state : State) (responseIndex : Nat) : Option State := do
  let .response .rw _ _ txid ← at? state.history responseIndex | none
  let latest ← state.branches.getLast?
  let entry ← at? latest txid.seqno
  guard (entry.view == txid.view)
  -- An earlier invalid report excludes the same-view suffix, even if it is still
  -- present in the newest branch.
  guard
    (!((statusIDs state.history .invalid).any
        fun invalid =>
          invalid.view == txid.view && invalid.seqno ≤ txid.seqno))
  -- Copied entries retain their original views, including across elections.
  guard
    (!((statusIDs state.history .invalid).any
        fun invalid =>
          invalid.seqno ≤ txid.seqno
          && match at? latest invalid.seqno with
              | some predecessor => predecessor.view == invalid.view
              | none => false))
  return appendEvent state (.status txid .committed)

/-- Report an invalid write. -/
def invalidate (state : State) (responseIndex : Nat) : Option State := do
  let .response .rw _ _ txid ← at? state.history responseIndex | none
  guard (mayInvalidate state txid)
  return appendEvent state (.status txid .invalid)

/-- Append a transaction that does not affect the dummy application. -/
def appendOther (state : State) (branch : Nat) : Option State := do
  guard (activeBranch state branch)
  return appendEntry state branch ⟨branch, none⟩

/-- Open the elected view using a prefix from an earlier view.
Only advancing the highest view changes the branch used for commitment. A late
leader must retain commitments known before its view was skipped, not those
made by newer views since then. -/
def elect (state : State) (view source prefixLength : Nat) : Option State := do
  guard (source < view && (source == 1 || activeBranch state source))
  let ledger ← at? state.branches source
  guard (prefixLength ≤ ledger.length)
  let latest := state.branches.length
  let retained := ledger.take prefixLength
  if latest < view then
    guard (hasCommittedPrefix state ledger)
    let frontier := commitSeqno state.history
    guard (frontier ≤ prefixLength)
    let gaps := view - latest - 1
    return {
      state with
        branches := state.branches ++ (List.replicate gaps [] ++ [retained])
        skipped := state.skipped ++ (List.range' (latest + 1) gaps).map (·, frontier)
    }
  else
    guard (view < latest && at? state.branches view == some [])
    let (_, frontier) ← state.skipped.find? (·.1 == view)
    let newest ← state.branches.getLast?
    guard (frontier ≤ prefixLength && ledger.take frontier == newest.take frontier)
    return {
      state with
        branches := state.branches.set (view - 1) retained
        skipped := state.skipped.filter (·.1 != view)
    }

/-- Dispatch an action to its guarded transition; `none` means the action is disabled. -/
def step (state : State) (action : Action) : Option State :=
  match action with
  | .request kind => request state kind
  | .execute requestIndex branch => execute state requestIndex branch
  | .respond requestIndex branch seqno => respond state requestIndex branch seqno
  | .read requestIndex branch => read state requestIndex branch
  | .commit responseIndex => commit state responseIndex
  | .invalidate responseIndex => invalidate state responseIndex
  | .appendOther branch => appendOther state branch
  | .elect view source prefixLength => elect state view source prefixLength

/-- An election preserves the history and extends existing ledgers.
Its only new nonempty ledger is the prefix copied into the elected view. -/
structure ElectionEffect (before after : State) (view source count : Nat) where
  ledger : List Entry
  found : at? before.branches source = some ledger
  earlier : source < view
  history : after.history = before.history
  extendsBranch
    : ∀ index old,
        at? before.branches index = some old
        → ∃ extended, at? after.branches index = some extended ∧ old <+: extended
  origin
    : ∀ index branch,
        at? after.branches index = some branch
        → at? before.branches index = some branch
          ∨ branch = []
          ∨ (index = view ∧ branch = ledger.take count)
  newest
    : at? after.branches after.branches.length
        = at? before.branches before.branches.length
      ∨ (at? after.branches after.branches.length = some (ledger.take count)
          ∧ hasCommittedPrefix before ledger = true
          ∧ commitSeqno before.history ≤ count)

private theorem guard_some {α : Type} {p : Prop} [Decidable p] {f : Unit → Option α}
    {a : α} (bound : ((if p then pure () else failure : Option Unit) >>= f) = some a)
    : p ∧ f () = some a := by
  by_cases holds : p
  · rw [ite_eq_left holds] at bound
    exact ⟨holds, bound⟩
  · rw [ite_eq_right holds] at bound
    cases bound

theorem elect_effect {before after : State} {view source count : Nat}
    (transition : step before (.elect view source count) = some after)
    : Nonempty (ElectionEffect before after view source count) := by
  unfold step elect at transition
  obtain ⟨allowed, transition⟩ := guard_some transition
  simp only [Bool.and_eq_true, decide_eq_true_eq] at allowed
  have earlier := allowed.1
  obtain ⟨ledger, found, transition⟩ := Option.bind_eq_some_iff.mp transition
  obtain ⟨_, transition⟩ := guard_some transition
  dsimp only at transition
  split at transition
  next advances =>
    obtain ⟨compatible, transition⟩ := guard_some transition
    obtain ⟨retained, transition⟩ := guard_some transition
    cases transition
    refine ⟨⟨ledger, found, earlier, rfl, ?_, ?_, Or.inr ⟨?_, compatible, retained⟩⟩⟩
    · intro index old lookup
      refine ⟨old, ?_, List.prefix_refl _⟩
      have nz : index ≠ 0 := by
        rintro rfl
        cases lookup
      simp only [at?, ite_eq_right nz] at lookup ⊢
      rw [List.getElem?_append_left ((List.getElem?_eq_some_iff.mp lookup).1)]
      exact lookup
    · intro index branch lookup
      by_cases nz : index = 0
      · subst index
        cases lookup
      simp only [at?, ite_eq_right nz] at lookup ⊢
      rw [List.getElem?_append] at lookup
      split at lookup
      · exact Or.inl lookup
      · rw [List.getElem?_append] at lookup
        simp only [List.length_replicate] at lookup
        split at lookup
        · simp_all
        · simp only [List.getElem?_cons] at lookup
          split at lookup
          · exact Or.inr (Or.inr ⟨by omega, Option.some.inj lookup.symm⟩)
          · cases lookup
    · have length : (before.branches ++
          (List.replicate (view - before.branches.length - 1) [] ++ [ledger.take count])).length =
          view := by
        simp only [List.length_append, List.length_replicate, List.length_cons, List.length_nil]
        omega
      change at? _ (before.branches ++
        (List.replicate (view - before.branches.length - 1) [] ++ [ledger.take count])).length = _
      rw [length, at?, ite_eq_right (by omega : view ≠ 0), List.getElem?_append_right (by omega),
        show view - 1 - before.branches.length = view - before.branches.length - 1 by omega,
        List.getElem?_append_right (by simp), List.length_replicate, Nat.sub_self]
      rfl
  next =>
    obtain ⟨openSlot, transition⟩ := guard_some transition
    obtain ⟨late, empty⟩ := (show view < before.branches.length ∧ at? before.branches view = some [] by
      simpa only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] using openSlot)
    obtain ⟨⟨_, frontier⟩, _, transition⟩ := Option.bind_eq_some_iff.mp transition
    obtain ⟨_, _, transition⟩ := Option.bind_eq_some_iff.mp transition
    obtain ⟨_, transition⟩ := guard_some transition
    cases transition
    have viewPos : view ≠ 0 := by
      rintro rfl
      cases empty
    have unchanged {index : Nat} (other : index ≠ view) :
        at? (before.branches.set (view - 1) (ledger.take count)) index =
          at? before.branches index := by
      by_cases nz : index = 0
      · simp [at?, nz]
      · simp only [at?, ite_eq_right nz, List.getElem?_set_ne (by omega : view - 1 ≠ index - 1)]
    have filled : at? (before.branches.set (view - 1) (ledger.take count)) view =
        some (ledger.take count) := by
      rw [at?, ite_eq_right viewPos, List.getElem?_set_self (by omega)]
    refine ⟨⟨ledger, found, earlier, rfl, ?_, ?_, Or.inl ?_⟩⟩
    · intro index old lookup
      by_cases same : index = view
      · subst index
        rw [empty] at lookup
        cases lookup
        exact ⟨ledger.take count, filled, List.nil_prefix⟩
      · exact ⟨old, (unchanged same).trans lookup, List.prefix_refl _⟩
    · intro index branch lookup
      by_cases same : index = view
      · subst index
        exact Or.inr (Or.inr ⟨rfl, Option.some.inj (lookup.symm.trans filled)⟩)
      · exact Or.inl ((unchanged same).symm.trans lookup)
    · simp only [List.length_set]
      exact unchanged (by omega)

theorem ElectionEffect.ledger_mem {before after : State} {view source count : Nat}
    (effect : ElectionEffect before after view source count) {branch : List Entry}
    (member : branch ∈ after.branches)
    : ∃ old ∈ before.branches, branch <+: old := by
  have mem_at {ledgers : List (List Entry)} {i : Nat} {value : List Entry}
      (lookup : at? ledgers i = some value) : value ∈ ledgers := by
    by_cases zero : i = 0
    · simp [at?, zero] at lookup
    · exact List.mem_of_getElem? (by simpa [at?, zero] using lookup)
  obtain ⟨index, lookup⟩ := List.mem_iff_getElem?.mp member
  have atBranch : at? after.branches (index + 1) = some branch := by simp [at?, lookup]
  have sourceMem := mem_at effect.found
  rcases effect.origin _ _ atBranch with old | empty | ⟨_, copied⟩
  · exact ⟨branch, mem_at old, List.prefix_refl _⟩
  · exact ⟨effect.ledger, sourceMem, empty ▸ List.nil_prefix⟩
  · exact ⟨effect.ledger, sourceMem, copied ▸ List.take_prefix _ _⟩

end consistency.Model
