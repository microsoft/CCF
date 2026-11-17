module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Suffix
public import CCF.Proofs.Finset

@[expose] public section

/-!
# M_tv is a `CCF.Sections.Refinement` of the clean node, given the obligations (not reviewed)

A section's events only extend the open hold: its head, delivered message and saved
declared state stay those of its first event, and the declared state at the last release
is unchanged. A release reruns the head's handler to completion from the saved state
(`runHold`), so the section is one hold of one handler, dispatched by the head's trace
point and, for deliveries, the message type (`dispatch`); `HoldSound` for that handler
(an `Obligations` field) gives its clean counterpart, given `inv` of the declared state
at release, which the release checks. Holds from the pristine genesis
primary have none: `genesisOk` makes them silent and keeps the clean initial state.
-/

namespace Consensus.TraceValidation.Proofs

open CCF.Sections
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State Ev Ctx Action)

theorem toOption_ok {ε α : Type} {x : Except ε α} {a : α} (h : x.toOption = some a)
    : x = .ok a := by
  cases x <;> simp_all [Except.toOption]

theorem decide_sound {p : Prop} (d : Decidable p) (h : @decide p d = true) : p := by
  cases d <;> simp_all

theorem sameVars_eq {a b : State} (h : sameVars a b = true) : a = b := by
  unfold sameVars at h
  exact decide_sound _ h

/-- Opening a hold records the head, the delivery and the saved declared state. -/
theorem stepE_idle {env : Env} {l l' : Local} {recv : Option (NodeID × Message)} {e : Ev}
    (idle : l.sec = none) (h : stepE env l recv e = .ok l')
    : exists a c,
        l'
          = {
            l with
              sec := some { head := e, recv, saved := l.vars, actions := [a], ctx := c }
          }
        /\ (opens e = true -> c.vars = l.vars) := by
  unfold stepE at h
  split at h
  · cases h
  · rename_i a _
    simp only [idle] at h
    split at h
    · cases h
    · rename_i c _
      split at h
      · cases h
      · split at h
        · cases h
        · rename_i keeps
          cases h
          refine ⟨a, c, rfl, fun hopens => ?_⟩
          simp only [hopens, Bool.true_and, Bool.not_eq_true'] at keeps
          exact sameVars_eq (by simpa using keeps)

/-- A later event of a hold only appends its action and moves the context. -/
theorem stepE_busy {env : Env} {l l' : Local} {s : Sec} {e : Ev}
    (busy : l.sec = some s) (h : stepE env l none e = .ok l')
    : exists a c,
        l' = { l with sec := some { s with actions := s.actions ++ [a], ctx := c } } := by
  unfold stepE at h
  split at h
  · cases h
  · rename_i a _
    simp only [busy] at h
    split at h
    · cases h
    · rename_i c _
      split at h
      · cases h
      · cases h
        exact ⟨a, c, rfl⟩

theorem steps_keep {env : Env} {node : NodeID}
    : forall {l f : Local} {events : List Ev} {s : Sec},
        Steps (machine env) node l events f
        -> l.sec = some s
        -> f.vars = l.vars
            /\ exists s',
                f.sec = some s'
                /\ s'.head = s.head
                /\ s'.recv = s.recv
                /\ s'.saved = s.saved
  | _, _, _, s, .nil _, busy => ⟨rfl, s, busy, rfl, rfl, rfl⟩
  | _, _, _, _, .cons step rest, busy => by
      obtain ⟨_, _, hm⟩ := stepE_busy busy (toOption_ok step)
      obtain ⟨hv, s', hs, h1, h2, h3⟩ := steps_keep rest (by rw [hm])
      refine ⟨by rw [hv, hm], s', hs, ?_, ?_, ?_⟩ <;> simp_all

theorem keepsInv_inv {names : Names} {saved vars : State}
    (saved_ : inv names saved = true) (h : keepsInv names saved vars = true)
    : inv names vars = true := by
  unfold keepsInv at h
  rcases Bool.or_eq_true_iff.mp h with same | holds
  · rw [sameVars_eq same]; exact saved_
  · exact holds

/-- What a successful release establishes. -/
theorem closeX_ok {env : Env} {others : List (NodeID × Local)} {l finish : Local}
    {sends : List (CCF.Envelope NodeID Message)} {c : Ctx}
    (h : closeX env others l = .ok (finish, sends, c))
    : exists s vars,
        l.sec = some s
        /\ runHold env s.saved s.recv s.head s.actions true = .ok c
        /\ closeVars others s.head c = .ok vars
        /\ genesisOk env s c vars = true
        /\ keepsInv env.names s.saved vars = true
        /\ baseOk vars = true
        /\ ghostFree env s c = true
        /\ finish = { vars }
        /\ sends = c.outbox := by
  unfold closeX at h
  split at h
  · cases h
  · rename_i s found
    dsimp only at h
    split at h
    · cases h
    · rename_i c' run
      split at h
      · cases h
      · rename_i vars cv
        split at h
        · rename_i ok
          split at h
          · rename_i holds
            split at h
            · rename_i based
              split at h
              · rename_i free
                simp only [Except.ok.injEq, Prod.mk.injEq] at h
                obtain ⟨rfl, rfl, rfl⟩ := h
                exact ⟨s, vars, found, run, cv, ok, holds, based, free, rfl, rfl⟩
              · cases h
            · cases h
          · cases h
        · cases h

theorem expand_declared {d : State} (zero : d.base = 0) : d.declared.expand = d := by
  cases d
  simp only at zero
  subst zero
  simp [State.declared, Exec.Declared.expand]

/--
A released hold's outcome is a function of the saved declared state: rerun from it, with
placeholders up to the snapshot base, it releases the same declared state and sends.
-/
theorem release_ghostFree {env : Env} {others : List (NodeID × Local)} {l finish : Local}
    {sends : List (CCF.Envelope NodeID Message)} {c : Ctx}
    (h : closeX env others l = .ok (finish, sends, c))
    : exists s c',
        l.sec = some s
        /\ runHold env s.saved.declared.expand s.recv s.head s.actions true = .ok c'
        /\ c'.vars.declared = c.vars.declared
        /\ c'.outbox = sends := by
  obtain ⟨s, _, found, run, _, _, _, _, free, _, rfl⟩ := closeX_ok h
  refine ⟨s, ?_⟩
  unfold ghostFree at free
  by_cases zero : s.saved.base = 0
  · exact ⟨c, found, by rw [expand_declared zero]; exact run, rfl, rfl⟩
  · have nonzero : (s.saved.base == 0) = false := by simpa using zero
    rw [nonzero, Bool.false_or] at free
    split at free
    · rename_i c' rerun
      simp only [Bool.and_eq_true, beq_iff_eq] at free
      exact ⟨c', found, rerun, free.1, free.2⟩
    · cases free

theorem close_ok {env : Env} {others : List (NodeID × Local)} {node : NodeID}
    {l finish : Local} {sends : List (CCF.Envelope NodeID Message)}
    (h : (machine env).close others node l = some (finish, sends))
    : exists c, closeX env others l = .ok (finish, sends, c) := by
  simp only [machine, Option.map_eq_some_iff] at h
  obtain ⟨⟨l', sends', c⟩, found, eq⟩ := h
  simp only [Prod.mk.injEq] at eq
  obtain ⟨rfl, rfl⟩ := eq
  exact ⟨c, toOption_ok found⟩

/-- A hold run to completion is one run of the head's handler. -/
theorem runHold_ok {env : Env} {saved : State} {recv : Option (NodeID × Message)}
    {head : Ev} {actions : List Action} {c : Ctx}
    (h : runHold env saved recv head actions true = .ok c)
    : isHead env saved head = true
      /\ exists hd,
          Exec.handlerFor head.function (recv.map fun (n, m) => (env.names.name n, m))
            = some hd
          /\ Exec.run env saved actions true hd = .ok c
          /\ c.queue = [] := by
  unfold runHold at h
  split at h
  · cases h
  · rename_i isHd
    simp only [Bool.not_eq_true', Bool.not_eq_false] at isHd
    refine ⟨by simpa using isHd, ?_⟩
    split at h
    · cases h
    · rename_i hd found
      split at h
      · rename_i c' run
        split at h
        · rename_i empty
          cases h
          exact ⟨hd, found, run, List.isEmpty_iff.mp empty⟩
        · cases h
      · cases h
      · cases h

theorem closeVars_plain {others : List (NodeID × Local)} {head : Ev}
    (other : head.function ≠ "init_as_backup")
    : (fun c => closeVars others head c) = plainFinish others := by
  funext c
  unfold closeVars plainFinish
  split
  · simp [other]
  · rfl

theorem closeVars_join {others : List (NodeID × Local)} {head : Ev}
    (join : head.function = "init_as_backup")
    : (fun c => closeVars others head c) = joinFinish others := by
  funext c
  unfold closeVars joinFinish
  split <;> simp_all

/-- `HoldSound` with the release's own `finish`. -/
def HoldSoundAt (env : Env) (node : NodeID) (recv : Option (NodeID × Message))
    (h : Exec.M Unit) (saved : State) (head : Ev)
    : Prop :=
  HoldSound env node recv h saved fun others c => closeVars others head c

theorem holdSoundAt {env : Env} {node : NodeID} {recv : Option (NodeID × Message)}
    {h : Exec.M Unit} {saved : State} {head : Ev}
    {finish : List (NodeID × Local) -> Ctx -> Except String State}
    (same : forall others, (fun c => closeVars others head c) = finish others)
    (sound : HoldSound env node recv h saved finish)
    : HoldSoundAt env node recv h saved head := by
  have : (fun others c => closeVars others head c) = finish := by
    funext others c
    exact congrFun (same others) c
  unfold HoldSoundAt
  rw [this]
  exact sound

/-- Every hold is one handler's hold, which its obligation covers. -/
theorem dispatch {env : Env} (ob : Obligations env) {node : NodeID} {saved : State}
    {recv : Option (NodeID × Message)} {head : Ev} {hd : Exec.M Unit}
    (isHd : isHead env saved head = true)
    (found
      : Exec.handlerFor head.function (recv.map fun (n, m) => (env.names.name n, m))
        = some hd)
    : HoldSoundAt env node recv hd saved head := by
  cases recv with
  | some p =>
      obtain ⟨source, message⟩ := p
      simp only [Option.map_some, Exec.handlerFor] at found
      split at found
      · rename_i isRecv
        cases found
        have other : head.function ≠ "init_as_backup" := by
          intro eq
          simp [eq, Exec.recvHeads] at isRecv
        apply holdSoundAt (fun others => closeVars_plain (others := others) other)
        have init : initialised saved = true := by
          simp only [isHead, Bool.and_eq_true, Bool.or_eq_true] at isHd
          rcases isHd.1 with init | allowed
          · exact init
          · simp [Exec.recvHeads] at isRecv
            rcases isRecv with eq | eq | eq | eq | eq <;> simp [eq, uninitialisedHeads] at allowed
        cases message with
        | appendEntriesRequest r => exact ob.appendEntries node source r saved
        | appendEntriesResponse r => exact ob.appendEntriesResponse node source r saved
        | requestVoteRequest r => exact ob.requestVote node source r saved
        | requestPreVoteRequest r => exact ob.requestPreVote node source r saved
        | requestVoteResponse r => exact ob.requestVoteResponse node source r saved init
        | requestPreVoteResponse r =>
            exact ob.requestPreVoteResponse node source r saved init
        | proposeRequestVoteRequest t =>
            exact ob.proposeRequestVote node source t saved init
      · cases found
  | none =>
      simp only [Option.map_none, Exec.handlerFor] at found
      split at found
      all_goals first
        | (cases found; done)
        | skip
      all_goals (cases found)
      · exact holdSoundAt (fun others => closeVars_plain (others := others) (by simp_all))
          (ob.dropPendingTo node saved)
      · exact holdSoundAt (fun others => closeVars_plain (others := others) (by simp_all))
          (ob.tick node saved)
      · exact holdSoundAt (fun others => closeVars_plain (others := others) (by simp_all))
          (ob.replicate node saved)
      · exact holdSoundAt (fun others => closeVars_plain (others := others) (by simp_all))
          (ob.nomination node saved)
      · exact holdSoundAt (fun others => closeVars_join (others := others) (by simp_all))
          (ob.initAsBackup node saved)
      · rename_i fn
        simp [isHead, uninitialisedHeads, opens, Exec.outOfLock, Exec.heads, Exec.recvHeads, fn] at isHd
        exact holdSoundAt (fun others => closeVars_plain (others := others) (by simp_all))
          (ob.outOfLockHook node saved isHd.1 isHd.2)
      · rename_i fn
        simp [isHead, uninitialisedHeads, opens, Exec.outOfLock, Exec.heads, Exec.recvHeads, fn] at isHd
        exact holdSoundAt (fun others => closeVars_plain (others := others) (by simp_all))
          (ob.forceBecomePrimary node saved isHd.1.1 isHd.1.2 isHd.2)

/-! ## The refinement -/

/--
A node's declared state at its last release, related to its clean state, and its snapshot
base checked (`baseOk`).
-/
def rel (env : Env) (node : NodeID) (c : NodeState) (l : Local) : Prop :=
  Rel env node c l.vars /\ baseOk l.vars = true

theorem inv_initial (names : Names) (nodeId : Exec.NodeId) (ticking : Bool)
    (named : names.name (names.id nodeId) = nodeId)
    : inv names { nodeId, ticking } = true := by
  simp [inv, invChecks, named, signaturesIn, State.isRetiredCommitted,
    Consensus.Model.Node.NodeState.isRetiredCommitted, Consensus.Model.Node.NodeState.retirement,
    Consensus.Model.Node.retirementIndexInLog, abs, Consensus.Model.Node.configurationHistory,
    Consensus.Model.Node.firstLogIndexAfter]

theorem agrees_initial {env : Env} {node : NodeID} {nodeId : Exec.NodeId} {ticking : Bool}
    (outside : node ∉ env.genesis)
    : agrees env.names (Consensus.Model.initialNodeState env.genesis node)
        { nodeId, ticking }
      = true := by
  have notMin : env.genesis.min? ≠ some node := by
    intro isMin
    exact outside (CCF.Finset.min?_mem isMin)
  simp [agrees, abs, absRole, trackedPeers, Consensus.Model.initialNodeState, outside, notMin]

theorem unnamedUnmatched_initial {genesis : CCF.Finset NodeID} {node : NodeID}
    : UnnamedUnmatched node (Consensus.Model.initialNodeState genesis node) := by
  intro _ _ _ _
  rfl

theorem keyed_rel {env : Env}
    : forall {others : List (NodeID × Local)} {cleanOthers : List (NodeID × NodeState)},
        Keyed (fun other local_ cleanOther => rel env other cleanOther local_) others
          cleanOthers
        -> Keyed (fun other local_ cleanOther => Rel env other cleanOther local_.vars)
            others cleanOthers
  | [], [], _ => .nil
  | _ :: _, _ :: _, .cons holds rest => .cons holds.1 (keyed_rel rest)

theorem section_sound {env : Env} (ob : Obligations env) (node : NodeID) (start : Local)
    (received : Option (NodeID × Message)) (events : List Ev) (middle finish : Local)
    (sends : List (CCF.Envelope NodeID Message)) (clean : NodeState)
    (others : List (NodeID × Local)) (cleanOthers : List (NodeID × NodeState))
    (idle : (machine env).idle start = true) (related_ : rel env node clean start)
    (recvInv
      : forall source message,
          received = some (source, message)
          -> msgInv env.names ⟨source, node, message⟩ = true)
    (run : SectionRun (machine env) node start received events middle)
    (closed : (machine env).close others node middle = some (finish, sends))
    (keyed
      : Keyed (fun other local_ cleanOther => rel env other cleanOther local_) others
          cleanOthers)
    : exists (inputs : List Input) (clean' : NodeState),
        LocalRun (protocol env) node clean (cleanActions env received inputs) clean' sends
        /\ rel env node clean' finish
        /\ (forall input, input ∈ inputs -> admit cleanOthers node input = true)
        /\ forall envelope, envelope ∈ sends -> msgInv env.names envelope = true := by
  obtain ⟨first, rest, mid0, rfl, firstStep, later⟩ := run
  have startIdle : start.sec = none := by simpa [machine, Local.idle] using idle
  obtain ⟨a, c0, hmid, _⟩ := stepE_idle startIdle (toOption_ok firstStep)
  obtain ⟨_, s, found, hhead, hrecv, hsaved⟩ := steps_keep later (by rw [hmid])
  simp only at hhead hrecv hsaved
  obtain ⟨c, closedX⟩ := close_ok closed
  obtain ⟨s', vars, found', ran, cv, genesis, inv', based, _, rfl, rfl⟩ := closeX_ok closedX
  rw [found] at found'
  cases found'
  obtain ⟨isHd, hd, hfound, hrun, hq⟩ := runHold_ok ran
  have sound := dispatch ob (node := node) isHd hfound
  obtain ⟨⟨rid, rid2, rinv, rdisj, unmatched⟩, _⟩ := related_
  rw [hsaved, hrecv] at sound
  rw [hsaved] at hrun
  have inv' : inv env.names vars = true := keepsInv_inv (by rw [hsaved]; exact rinv) inv'
  obtain ⟨nid, cond⟩ :=
    sound s.actions c vars others cleanOthers rid rid2 rinv recvInv
      (keyed_rel keyed) hrun hq cv inv'
  have vid : vars.nodeId = env.names.name node := nid.trans rid
  have vid2 : env.names.id vars.nodeId = node := by rw [nid]; exact rid2
  rcases rdisj with ⟨notPristine, agreed⟩ | ⟨isPristine, rfl⟩
  · have stays : pristine env vars = false := by
      have notPristine' : pristine env s.saved = false := by rw [hsaved]; exact notPristine
      simpa [genesisOk, notPristine'] using genesis
    obtain ⟨inputs, clean', lr, agreed', unmatched', admitted, sent⟩ :=
      cond clean notPristine agreed unmatched
    exact ⟨
      inputs,
      clean',
      lr,
      ⟨⟨vid, vid2, inv', Or.inl ⟨stays, agreed'⟩, unmatched'⟩, based⟩,
      admitted,
      sent
    ⟩
  · have pristineSaved : pristine env s.saved = true := by rw [hsaved]; exact isPristine
    simp only [genesisOk, pristineSaved, ite_true, Bool.and_eq_true,
      Option.isNone_iff_eq_none, List.isEmpty_iff, Bool.or_eq_true] at genesis
    obtain ⟨⟨noRecv, silent⟩, after⟩ := genesis
    rw [hrecv] at noRecv
    subst noRecv
    refine ⟨
      [],
      Consensus.Model.initialNodeState env.genesis node,
      ?_,
      ⟨⟨vid, vid2, inv', ?_, unmatched⟩, based⟩,
      by intro _ member; simp at member,
      ?_
    ⟩
    · rw [silent]
      exact LocalRun.nil _
    · by_cases still : pristine env vars = true
      · exact Or.inr ⟨still, rfl⟩
      · rcases after with stays | agreed
        · exact absurd stays still
        · rw [vid2] at agreed
          exact Or.inl ⟨by simpa using still, agreed⟩
    · rw [silent]
      intro _ member
      simp at member

/-- M_tv refines the clean node, section by section, given every handler's obligation. -/
def refinement (env : Env) (ob : Obligations env)
    : Refinement (machine env) (protocol env) admit where
  msgInv envelope := msgInv env.names envelope = true
  rel := rel env
  init_sound node l initial := by
    obtain ⟨roundTrip, genesisMin, ticking, rfl⟩ := initial
    refine ⟨
      rfl,
      _,
      rfl,
      ⟨
        rfl,
        roundTrip,
        inv_initial _ _ _ (by rw [roundTrip]),
        ?_,
        unnamedUnmatched_initial
      ⟩,
      rfl
    ⟩
    by_cases isMin : env.genesis.min? = some node
    · refine Or.inr ⟨?_, rfl⟩
      simp [pristine, initialLocal, isMin, roundTrip]
    · have outside : node ∉ env.genesis := fun member => isMin (genesisMin member)
      refine Or.inl ⟨?_, agrees_initial outside⟩
      simp [pristine, initialLocal, isMin, roundTrip]
  section_sound := by
    intro node start received events middle finish sends clean others cleanOthers idle related_
      recvInv run closed _ keyed
    exact section_sound ob node start received events middle finish sends clean others
      cleanOthers idle related_ recvInv run closed keyed

/-- Idle states are `related`, as `declare` sees them. -/
theorem factors (env : Env) (node : NodeID) (c : NodeState) (l : Local)
    (h : rel env node c l) (idle : (machine env).idle l = true)
    : related env.names node c (declare l).1 = true := by
  have none_ : l.sec = none := by simpa [machine, Local.idle] using idle
  have : (declare l).1 = l.vars.declared := by simp [declare, none_]
  rw [this]
  exact related_declared h.1 h.2

/-- A lock-taking event leaves the declared state as it was at release. -/
theorem frame (env : Env) (node : NodeID) (l : Local)
    (received : Option (NodeID × Message)) (e : Ev) (l' : Local)
    (idle : (machine env).idle l = true)
    (h : (machine env).step node l received e = some l')
    (hopens : (machine env).opens e = true)
    : forall c,
        related env.names node c (declare l).1 = true
        -> related env.names node c (declare l').1 = true := by
  have none_ : l.sec = none := by simpa [machine, Local.idle] using idle
  obtain ⟨_, _, rfl, keeps⟩ := stepE_idle none_ (toOption_ok h)
  intro c hc
  simpa [declare, none_, keeps hopens] using hc

end Consensus.TraceValidation.Proofs
