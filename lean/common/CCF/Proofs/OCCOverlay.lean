module

public import CCF.Proofs.OCC

@[expose] public section

namespace CCF.OCC

variable {K V W M : Type}

private theorem erase_comm [DecidableEq K] (xs : Assoc K V) (a b : K) :
    erase (erase xs a) b = erase (erase xs b) a := by
  simp [erase, List.filter_filter, Bool.and_comm]

private theorem erase_writeValues [DecidableEq K] (xs : Assoc K V)
    (ws : Assoc K (Option V)) (key : K) :
    erase (writeValues xs (erase ws key)) key = erase (writeValues xs ws) key := by
  induction ws with
  | nil => rfl
  | cons w ws ih =>
    obtain ⟨a,v⟩ := w
    by_cases h : a = key
    · subst a
      cases v <;> simpa [writeValues, erase, set, List.filter_filter] using ih
    · have keep {T : Type} (x : T) (l : Assoc K T) :
          erase ((a,x)::l) key = (a,x)::erase l key := by simp [erase,h]
      rw [keep]
      have rest := congrArg (erase · a) ih
      rw [erase_comm _ key a, erase_comm (writeValues xs ws) key a] at rest
      cases v with
      | none => exact rest
      | some x =>
        change erase ((a,x)::_) key = erase ((a,x)::_) key
        rw [keep,keep]
        exact congrArg ((a,x) :: ·) rest

/-- Staging a write and then overlaying it is the same as updating the overlay. -/
theorem writeValues_set [DecidableEq K] (xs : Assoc K V) (ws : Assoc K (Option V))
    (k : K) (v : Option V) : writeValues xs (set ws k v) =
    match v with
    | none => erase (writeValues xs ws) k
    | some x => set (writeValues xs ws) k x := by
  cases v with
  | none => exact erase_writeValues xs ws k
  | some x => exact congrArg ((k,x) :: ·) (erase_writeValues xs ws k)

/-- The committed associations without their version stamps. -/
def values (db : DB M K V) : Assoc (Addr M K) V :=
  db.map fun (a,c) => (a,c.value)

private theorem map_erase [DecidableEq K] (f : K → V → W) (xs : Assoc K V) (k : K) :
    (erase xs k).map (fun (a,v) => (a,f a v)) = erase (xs.map (fun (a,v) => (a,f a v))) k := by
  simp [erase, List.filter_map, Function.comp_def]

/-- The value-level overlay of all tables seen by a running transaction. -/
def overlay [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V) :
    Assoc (Addr M K) V := writeValues (values db) ws

/-- Publication changes versions but has exactly the values seen through the overlay. -/
theorem overlay_publish [DecidableEq M] [DecidableEq K] (db : DB M K V)
    (ws : Writes M K V) (version : Nat) :
    overlay (publish db version ws) [] = overlay db ws := by
  change values (publish db version ws) = writeValues (values db) ws
  induction ws with
  | nil => rfl
  | cons w ws ih =>
    rcases w with ⟨a,v⟩
    have tail := (map_erase (fun (_ : Addr M K) (c : Cell V) => c.value) (publish db version ws) a).trans
      (congrArg (erase · a) ih)
    cases v with
    | none => exact tail
    | some x => exact congrArg ((a,x) :: ·) tail

private theorem find_values [DecidableEq M] [DecidableEq K] (db : DB M K V) (a : Addr M K) :
    find (values db) a = (find db a).map Cell.value := by
  induction db with
  | nil => rfl
  | cons p db ih =>
    obtain ⟨b,c⟩ := p
    by_cases h : b = a <;> simp_all [values, find]

/-- Point reads see exactly the lookup in the value-level overlay. -/
theorem find_overlay [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
    (a : Addr M K) : find (overlay db ws) a = valueAt db ws a := by
  have h := congrArg (Option.map Cell.value) (publish_lookup db 0 ws a)
  rw [← find_values, show values (publish db 0 ws) = overlay db ws from overlay_publish db ws 0] at h
  cases w : find ws a with
  | none => simpa [w,valueAt] using h
  | some v => cases v <;> simpa [w,valueAt] using h

/-- Select a table from the associations of a value-level store. -/
def entriesOf [DecidableEq M] {T : Type} (xs : Assoc (Addr M K) T) (m : M) : Assoc K T :=
  xs.filterMap fun ((t,k),v) => if t = m then some (k,v) else none

theorem entriesOf_erase [DecidableEq M] [DecidableEq K] {T : Type}
    (xs : Assoc (Addr M K) T) (t m : M) (k : K) :
    entriesOf (erase xs (t,k)) m =
      if t = m then erase (entriesOf xs m) k else entriesOf xs m := by
  induction xs with
  | nil => by_cases h : t = m <;> simp [entriesOf,erase,h]
  | cons p xs ih =>
    obtain ⟨⟨u,j⟩,v⟩ := p
    by_cases ht : t = m <;> by_cases hu : u = t <;> by_cases hm : u = m <;>
      by_cases hk : j = k <;> simp_all [entriesOf,erase]

/-- Scanning the overlay includes its staged writes in the same order as `scanAt`. -/
theorem entriesOf_overlay [DecidableEq M] [DecidableEq K] (db : DB M K V)
    (ws : Writes M K V) (m : M) : entriesOf (overlay db ws) m = scanAt db ws m := by
  induction ws with
  | nil =>
    simp [entriesOf,overlay,values,scanAt,image,writeValues,List.filterMap_map,
      List.map_filterMap,Function.comp_def]
  | cons w ws ih =>
    obtain ⟨⟨t,k⟩,v⟩ := w
    have cons {T : Type} (c : T) (xs : Assoc (Addr M K) T) :
        entriesOf (((t,k),c)::xs) m = if t = m then (k,c)::entriesOf xs m else entriesOf xs m := by
      by_cases h : t = m <;> simp [entriesOf,h]
    cases v with
    | none =>
      change entriesOf (erase (overlay db ws) (t,k)) m = _
      rw [entriesOf_erase]
      by_cases h : t = m <;> simp [scanAt,writeValues,h] at ih ⊢ <;> rw [ih]
    | some x =>
      change entriesOf (((t,k),x)::erase (overlay db ws) (t,k)) m = _
      rw [cons,entriesOf_erase]
      by_cases h : t = m <;> simp [scanAt,writeValues,set,h] at ih ⊢ <;> rw [ih]

/-- Execute directly on value associations. Only successful executions expose their
final store and outputs; failures roll back. -/
def Program.serial {α O : Type} [DecidableEq M] [DecidableEq K]
    (xs : Assoc (Addr M K) V) (outs : List O) : Program M K V O α →
      Except String (α × Assoc (Addr M K) V × List O)
  | .done x => .ok (x,xs,outs)
  | .fail reason => .error reason
  | .get a next => (next (find xs a)).serial xs outs
  | .scan m next => (next (entriesOf xs m)).serial xs outs
  | .put a none next => next.serial (erase xs a) outs
  | .put a (some v) next => next.serial (set xs a v) outs
  | .output o next => next.serial xs (outs ++ [o])

/-- The serial interpretation composes with transaction-program sequencing. -/
theorem Program.serial_bind {α β O : Type} [DecidableEq M] [DecidableEq K]
    (xs : Assoc (Addr M K) V) (outs : List O) (p : Program M K V O α)
    (f : α → Program M K V O β) :
    (p.bind f).serial xs outs =
      (p.serial xs outs).bind (fun (x,ys,o) => (f x).serial ys o) := by
  induction p generalizing xs outs with
  | done | fail => rfl
  | get _ _ ih | scan _ _ ih => exact ih _ _ _
  | put _ v _ ih => cases v <;> exact ih _ _
  | output _ _ ih => exact ih _ _

/-- Serial execution has exactly the outcome of running on a snapshot and publishing
the successful writes, including the order of every scan and output. -/
theorem Program.serial_eq_execFrom {α O : Type} [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (n : Normal M K V) (outs : List O) (p : Program M K V O α) :
    let ran := p.execFrom db n outs
    p.serial (overlay db n.writes) outs =
      ran.result.map (fun x => (x,overlay db ran.normal.writes,ran.outputs)) := by
  induction p generalizing n outs with
  | done | fail => rfl
  | output _ _ ih => exact ih _ _
  | get a next ih =>
    simp only [Program.serial,find_overlay,Program.execFrom]
    exact ih _ (recordOp db n (.read a _)) _
  | scan m next ih =>
    simp only [Program.serial,entriesOf_overlay,Program.execFrom]
    exact ih _ (recordOp db n (.scan m _)) _
  | put a v next ih =>
    have h := ih (recordOp db n (.write a v)) outs
    cases v <;> simpa [Program.execFrom,Program.serial,recordOp,stage,overlay,writeValues_set] using h

end CCF.OCC
