module

public import CCF.OCC

@[expose] public section

namespace CCF.OCC

variable {M K V O α : Type}

/-- A scan may return a map in any enumeration order. Such a program always
continues with the same instructions when only that order changes. -/
def Program.Respects : Program M K V O α → Prop
  | .done _ | .fail _ => True
  | .get _ next => ∀ value, (next value).Respects
  | .scan _ next =>
      (∀ xs ys, xs.Perm ys → next xs = next ys) ∧ ∀ xs, (next xs).Respects
  | .put _ _ rest | .output _ rest => rest.Respects

private theorem find_set_same [DecidableEq K] (xs : Assoc K V) (k : K) (v : V)
    : find (set xs k v) k = some v := by
  simp [set, find]

private theorem find_erase_same [DecidableEq K] (xs : Assoc K V) (k : K)
    : find (erase xs k) k = none := by
  induction xs with
  | nil => rfl
  | cons p xs ih =>
      rcases p with ⟨a, v⟩
      by_cases h : a = k <;> simp_all [erase, find]

private theorem find_erase_other [DecidableEq K] (xs : Assoc K V) (a k : K) (h : a ≠ k)
    : find (erase xs a) k = find xs k := by
  induction xs with
  | nil => rfl
  | cons p xs ih =>
      rcases p with ⟨b, v⟩
      by_cases hba : b = a <;> by_cases hbk : b = k <;> simp_all [erase, find]

private theorem find_set_other [DecidableEq K] (xs : Assoc K V) (a k : K) (v : V)
    (h : a ≠ k)
    : find (set xs a v) k = find xs k := by
  simp [set, find, h, find_erase_other xs a k h]

/-- Looking up a key after setting a single association. -/
theorem find_set_eq [DecidableEq K] (xs : Assoc K V) (id key : K) (v : V)
    : find (set xs id v) key = if id = key then some v else find xs key := by
  by_cases h : id = key <;> simp [h, find_set_same, find_set_other]

private theorem erase_keys [DecidableEq K] (xs : Assoc K V) (k : K)
    : (erase xs k).map Prod.fst = (xs.map Prod.fst).filter (· != k) :=
  (List.filter_map (f := Prod.fst) (p := (· != k)) (l := xs)).symm

private theorem erase_unique [DecidableEq K] (xs : Assoc K V) (k : K) (h : (xs.map Prod.fst).Nodup)
    : ((erase xs k).map Prod.fst).Nodup := by
  rw [erase_keys]
  exact List.Pairwise.filter _ h

private theorem set_unique [DecidableEq K] (xs : Assoc K V) (k : K) (v : V) (h : (xs.map Prod.fst).Nodup)
    : ((set xs k v).map Prod.fst).Nodup := by
  simp only [set, List.map_cons, List.nodup_cons]
  constructor
  · simp [erase_keys, eq_comm]
  · exact erase_unique xs k h

/-- Publication agrees with staged writes, leaving every other cell unchanged. -/
theorem publish_lookup [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat) (ws : Writes M K V)
    (a : Addr M K)
    : find (publish db version ws) a
      = match find ws a with
        | none => find db a
        | some none => none
        | some (some v) => some { value := v, version } := by
  induction ws with
  | nil => rfl
  | cons p ws ih =>
      rcases p with ⟨b, value⟩
      by_cases h : b = a
      · subst b
        cases value <;> simp [publish, find, find_set_same, find_erase_same]
      · cases value <;> simp [publish, find, h, find_set_other, find_erase_other, ← ih, publish]

/-- Publishing any write set preserves the uniqueness of store addresses. -/
theorem publish_unique [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat) (ws : Writes M K V)
    (h : (db.map Prod.fst).Nodup)
    : ((publish db version ws).map Prod.fst).Nodup := by
  induction ws with
  | nil => exact h
  | cons p ws ih =>
      rcases p with ⟨a, v⟩
      cases v with
      | none => exact erase_unique _ a ih
      | some value => exact set_unique _ a ⟨value, version⟩ ih

private theorem overlay_perm [DecidableEq K] (xs ys : Assoc K V) (writes : Assoc K (Option V))
    (h : xs.Perm ys) : (writeValues xs writes).Perm (writeValues ys writes) := by
  induction writes with
  | nil => exact h
  | cons w _ ih =>
      obtain ⟨k, v⟩ := w
      cases v with
      | none => exact ih.filter _
      | some _ => exact (ih.filter _).cons _

variable [DecidableEq M] [DecidableEq K] [DecidableEq V]

private theorem valid_prefix (snap db : DB M K V) (n : Normal M K V) (outs : List O)
    (body : Program M K V O α) :
    validates db (body.execFrom snap n outs).normal.deps = true → validates db n.deps = true := by
  induction body generalizing n outs with
  | done | fail => exact id
  | output _ _ ih => apply ih
  | get _ _ ih | scan _ _ ih =>
      intro h
      have valid := ih _ _ _ h
      simp only [recordOp, validates, List.all_append, Bool.and_eq_true] at valid
      exact valid.2
  | put addr value _ ih =>
      intro h
      exact ih (recordOp snap n (.write addr value)) outs h

/-- Executing a program on its own snapshot produces valid dependencies. -/
theorem Program.exec_valid (snap : DB M K V) (body : Program M K V O α) :
    validates snap (body.exec snap).normal.deps = true := by
  suffices ∀ n outs, validates snap n.deps = true →
      validates snap (body.execFrom snap n outs).normal.deps = true from this {} [] rfl
  induction body with
  | done | fail => intros; assumption
  | output _ _ ih => intros; apply ih; assumption
  | put _ _ _ ih => intros; apply ih; assumption
  | get _ _ ih =>
      intro n outs valid
      apply ih
      simpa [recordOp, needs, validates, Dependency.holds] using valid
  | scan _ _ ih =>
      intro n outs valid
      apply ih
      simpa [recordOp, needs, validates, Dependency.holds] using valid

/-- Observable results of execution, excluding the dependency certificate and log. -/
def Program.Ran.observable (ran : Program.Ran M K V O α) :=
  (ran.normal.writes, ran.outputs, ran.result)

private theorem replayFrom (snap db : DB M K V) (n n' : Normal M K V) (outs : List O)
    (body : Program M K V O α) (respect : body.Respects) (writes : n.writes = n'.writes)
    (valid : validates db (body.execFrom snap n outs).normal.deps = true) :
    (body.execFrom snap n outs).observable = (body.execFrom db n' outs).observable := by
  induction body generalizing n n' outs with
  | done | fail => simpa [Program.execFrom, Program.Ran.observable] using writes
  | output _ _ ih => exact ih _ _ _ respect writes valid
  | put _ _ _ ih =>
      apply ih _ _ _ respect _ valid
      simp [recordOp, stage, writes]
  | get addr next ih =>
      let v := valueAt snap n.writes addr
      have ok := valid_prefix snap db (recordOp snap n (.read addr v)) outs (next v) valid
      have same : v = valueAt db n'.writes addr := by
        cases hw : find n.writes addr with
        | some _ => simp [v, valueAt, ← writes, hw]
        | none =>
            have eq : find db addr = find snap addr := by
              simp only [recordOp, validates, List.all_append, Bool.and_eq_true] at ok
              simpa [needs, hw, Dependency.holds] using ok.1
            simp [v, valueAt, ← writes, hw, eq]
      simp only [Program.execFrom, ← same]
      exact ih v _ _ _ (respect v) writes valid
  | scan m next ih =>
      let xs := scanAt snap n.writes m
      let ys := scanAt db n'.writes m
      have ok := valid_prefix snap db (recordOp snap n (.scan m xs)) outs (next xs) valid
      have images : (image db m).Perm (image snap m) := by
        simp only [recordOp, validates, List.all_append, Bool.and_eq_true] at ok
        simpa [needs, Dependency.holds] using ok.1
      have perm : xs.Perm ys := by
        unfold xs ys scanAt
        rw [← writes]
        exact overlay_perm _ _ _ (images.symm.map _)
      change _ = ((next ys).execFrom db (recordOp db n' (.scan m ys)) outs).observable
      rw [← respect.1 xs ys perm]
      exact ih xs _ _ _ (respect.2 xs) writes valid

/-- Replaying a validated program that ignores scan enumeration order reproduces
its writes, ordered outputs and result, even for stores with duplicate keys. -/
theorem Program.exec_replay (snap db : DB M K V) (body : Program M K V O α)
    (respect : body.Respects) (valid : validates db (body.exec snap).normal.deps = true) :
    (body.exec snap).observable = (body.exec db).observable :=
  replayFrom snap db {} {} [] body respect rfl valid

end CCF.OCC
