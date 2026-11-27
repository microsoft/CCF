module

public import CCF.Proofs.OCCOverlay
public import DisasterRecovery.Proofs.Atomic

@[expose] public section

namespace DisasterRecovery.Proofs.Atomic

open CCF.OCC
open Model.Local (Table Key Value Store)

/-- A version-free view of all cells in a node's store. -/
abbrev Rows := Assoc (Addr Table Key) Value

private def gossipRow (g : Location × TxID) : Key × Value := (some g.1,.txid g.2)
private def voteRow (s : Location) : Key × Value := (some s,.present)

/-- All rows of one table in the atomic state. -/
def rows (s : NodeState) : Table → Assoc Key Value
  | .phase => [(none,.phase s.phase)]
  | .timeoutPhase => [(none,.phase s.timeoutState)]
  | .chosen => s.chosen.toList.map fun c => (none,.location c)
  | .openKind => s.openKind.toList.map fun k => (none,.openKind k)
  | .gossips => s.gossips.map fun g => (some g.1,.txid g.2)
  | .votes => s.votes.map fun v => (some v,.present)

/-- Exact agreement of every typed table, including enumeration order. -/
structure Represents (xs : Rows) (s : NodeState) : Prop where
  /-- All six table enumerations agree with the abstract fields. -/
  tables : ∀ t, entriesOf xs t = rows s t
  /-- The vote table contains at most one row per voter. -/
  votes : s.votes.Nodup

theorem represents_initial (location : Location)
    : Represents (values Model.Local.initialStore) (initialNode location) :=
  ⟨by intro t; cases t <;> rfl, by simp [initialNode]⟩

private theorem find_table (xs : Rows) (t : Table) (k : Key)
    : find xs (t,k) = find (entriesOf xs t) k := by
  induction xs with
  | nil => rfl
  | cons row xs ih =>
      obtain ⟨⟨u,j⟩,v⟩ := row
      by_cases h : u = t <;> by_cases h' : j = k <;> simp_all [entriesOf,find]

theorem Represents.read {xs : Rows} {s : NodeState} (r : Represents xs s) (t : Table)
    (k : Key)
    : find xs (t,k) = find (rows s t) k := by rw [find_table,r.tables]

theorem Represents.scanGossips {xs : Rows} {s : NodeState} (r : Represents xs s)
    : Model.Local.gossipEntries (entriesOf xs .gossips) = s.gossips := by
  simp [r.tables,rows,Model.Local.gossipEntries,List.filterMap_map, Function.comp_def]

theorem Represents.scanVotes {xs : Rows} {s : NodeState} (r : Represents xs s)
    : Model.Local.voteEntries (entriesOf xs .votes) = s.votes := by
  simp [r.tables,rows,Model.Local.voteEntries,List.filterMap_map,Function.comp_def]

private theorem put {xs : Rows} {s : NodeState} (r : Represents xs s)
    (t : Table) (k : Key) (v : Value) (s' : NodeState)
    (same : ∀ u, rows s' u = if t = u then set (rows s u) k v else rows s u)
    (votes : s'.votes.Nodup)
    : Represents (set xs (t,k) v) s' := by
  refine ⟨fun u => ?_,votes⟩
  have head : entriesOf (set xs (t,k) v) u =
      if t = u then (k,v) :: entriesOf (erase xs (t,k)) u else entriesOf (erase xs (t,k)) u := by
    by_cases h : t = u <;> simp [entriesOf,CCF.OCC.set,h]
  rw [head, entriesOf_erase, r.tables, same]
  split <;> rfl

theorem Represents.phase {xs : Rows} {s : NodeState} (r : Represents xs s) (p : Phase)
    : Represents (set xs (.phase,none) (.phase p)) {s with phase := p} := by
  apply put r
  case votes => exact r.votes
  intro u; cases u <;> rfl

theorem Represents.lane {xs : Rows} {s : NodeState} (r : Represents xs s) (p : Phase)
    : Represents (set xs (.timeoutPhase,none) (.phase p)) {s with timeoutState := p} := by
  apply put r
  case votes => exact r.votes
  intro u; cases u <;> rfl

theorem Represents.chosen {xs : Rows} {s : NodeState} (r : Represents xs s) (c : Location)
    : Represents (set xs (.chosen,none) (.location c)) {s with chosen := some c} := by
  apply put r
  case votes => exact r.votes
  intro u; cases u <;> first | rfl | simp only [rows]; cases s.chosen <;> rfl

theorem Represents.kind {xs : Rows} {s : NodeState} (r : Represents xs s) (k : OpenKind)
    : Represents (set xs (.openKind,none) (.openKind k)) {s with openKind := some k} := by
  apply put r
  case votes => exact r.votes
  intro u; cases u <;> first | rfl | simp only [rows]; cases s.openKind <;> rfl

private theorem gossip_absent (gs : List (Location × TxID)) (src : Location)
    : (find (gs.map gossipRow) (some src)).isNone = !gs.any (fun g => g.1 == src) := by
  induction gs with
  | nil => rfl
  | cons g gs ih =>
      by_cases h : g.1 = src <;> simp_all [find,gossipRow]

theorem Represents.gossipAbsent {xs : Rows} {s : NodeState} (r : Represents xs s)
    (src : Location)
    : (find xs (.gossips,some src)).isNone = !s.gossips.any (·.1 == src) := by
  rw [r.read]
  exact gossip_absent _ _

theorem Represents.gossip {xs : Rows} {s : NodeState} (r : Represents xs s)
    (src : Location) (txid : TxID) (missing : s.gossips.any (·.1 == src) = false)
    : Represents (set xs (.gossips,some src) (.txid txid))
        {s with gossips := insertGossip src txid s.gossips} := by
  apply put r
  case votes => exact r.votes
  intro u
  cases u <;> first | rfl | skip
  simp [rows,insertGossip,missing,CCF.OCC.set,erase,List.filter_map,Function.comp_def]
  congr 1
  symm
  apply List.filter_eq_self.mpr
  simpa [bne_iff_ne] using missing

theorem Represents.vote {xs : Rows} {s : NodeState} (r : Represents xs s) (src : Location)
    : Represents (set xs (.votes,some src) .present)
        {s with votes := insertVote src s.votes} := by
  apply put r
  · intro u
    cases u <;> first | rfl | skip
    simp [rows,insertVote,CCF.OCC.set,erase,List.filter_map,Function.comp_def]
    congr 1
    rw [r.votes.erase_eq_filter]
    apply List.filter_congr
    intro x _
    by_cases h : x = src
    · simp [h]
    · have ne : (some x : Key) ≠ some src := by simpa using h
      rw [bne_iff_ne.mpr h]
      change true = !decide (some x = some src)
      simp [ne]
  · exact List.nodup_cons.mpr ⟨r.votes.not_mem_erase, r.votes.erase _⟩

/-- The atomic state projected from a model node. -/
def project (s : Model.Local.NodeState) : NodeState :=
  ⟨s.location,s.phase,s.timeoutState,s.gossips,s.votes,s.chosen,s.openKind⟩

theorem Represents.project {st : Model.Local.NodeState} {s : NodeState}
    (r : Represents (values st.store) s) (loc : st.location = s.location)
    : project st = s := by
  have point (t : Table) : Model.Local.single st.store t = find (rows s t) none :=
    (find_overlay st.store [] (t,none)).symm.trans (r.read t none)
  have gs : st.gossips = s.gossips := by
    change Model.Local.gossipEntries (scanAt st.store [] .gossips) = _
    rw [← entriesOf_overlay]
    exact r.scanGossips
  have vs : st.votes = s.votes := by
    change Model.Local.voteEntries (scanAt st.store [] .votes) = _
    rw [← entriesOf_overlay]
    exact r.scanVotes
  cases s with
  | mk location ph lane gossips votes chosen kind =>
      cases chosen <;> cases kind <;>
        simp [Atomic.project, Model.Local.NodeState.phase, Model.Local.NodeState.timeoutState,
          Model.Local.NodeState.chosen, Model.Local.NodeState.openKind, point, rows, find,
          loc,gs,vs]

end DisasterRecovery.Proofs.Atomic
