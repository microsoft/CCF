module

public import CCF.Sections
public import CCF.Proofs.Execution

@[expose] public section

namespace CCF.Sections

/-!
The lifting step: a `Refinement` makes every step of the event-granular network a
(possibly empty) run of the guarded clean network, preserving a simulation relation.
Event and delivery steps are matched by no clean step; a release is matched by the
section's clean local run.
-/

open MultiNodeTransitionSystem (nodeState removeOne)
open Execution (Run)

/-- `guard` in `Option`, as a conditional. -/
theorem option_guard_bind {α : Type} (p : Prop) [Decidable p] (f : Unit -> Option α)
    : (guard p : Option Unit).bind f = if p then f () else none := by
  by_cases h : p <;> simp [h, guard, pure, failure]

section TableLemmas

variable {Node LocalState Message : Type} [BEq Node] [LawfulBEq Node]

/-- A found entry is a member of the node table, under its own key. -/
theorem mem_of_nodeState {state : MultiNodeTransitionSystem.State Node LocalState Message}
    {node : Node} {value : LocalState} (found : nodeState state node = some value)
    : (node, value) ∈ state.nodes := by
  unfold nodeState at found
  obtain ⟨entry, hfind, rfl⟩ := Option.map_eq_some_iff.mp found
  have hkey := List.find?_some hfind
  have hmem := List.mem_of_find?_eq_some hfind
  simp only [beq_iff_eq] at hkey
  subst hkey
  exact hmem

/-- Overwriting preserves the key list. -/
theorem keys_setNode (state : MultiNodeTransitionSystem.State Node LocalState Message)
    (node : Node) (value : LocalState)
    : (setNode state node value).nodes.map Prod.fst = state.nodes.map Prod.fst := by
  simp only [setNode, List.map_map]
  apply List.map_congr_left
  intro entry _
  by_cases h : entry.1 = node <;> simp [h]

/-- Members of an overwritten table are the new entry or old members. -/
theorem mem_setNode {state : MultiNodeTransitionSystem.State Node LocalState Message}
    {node : Node} {value : LocalState} {entry : Node × LocalState}
    (member : entry ∈ (setNode state node value).nodes)
    : entry = (node, value) \/ entry ∈ state.nodes := by
  simp only [setNode, List.mem_map] at member
  obtain ⟨old, hold, rfl⟩ := member
  by_cases h : old.1 = node <;> simp [h, hold]

/-- Overwriting a present node makes the lookup return the new value. -/
theorem nodeState_setNode
    {state : MultiNodeTransitionSystem.State Node LocalState Message} {node : Node}
    {old value : LocalState} (found : nodeState state node = some old)
    : nodeState (setNode state node value) node = some value := by
  unfold nodeState at found ⊢
  simp only [setNode, List.find?_map]
  have hcomp : ((fun entry : Node × LocalState => entry.1 == node)
      ∘ fun entry => if entry.1 == node then (node, value) else entry)
      = fun entry => entry.1 == node := by
    funext entry
    by_cases h : entry.1 = node <;> simp [h]
  rw [hcomp]
  obtain ⟨entry, hfind, _⟩ := Option.map_eq_some_iff.mp found
  rw [hfind]
  have hkey := List.find?_some hfind
  simp [hkey]

/-- Two overwrites of the same node keep the last value. -/
theorem setNode_setNode (state : MultiNodeTransitionSystem.State Node LocalState Message)
    (node : Node) (first second : LocalState)
    : setNode (setNode state node first) node second = setNode state node second := by
  simp only [setNode, List.map_map]
  congr 2
  funext entry
  by_cases h : entry.1 = node <;> simp [h]

private theorem map_set_absent (entries : List (Node × LocalState)) (node : Node)
    (value : LocalState) (absent : forall entry, entry ∈ entries -> entry.1 ≠ node)
    : entries.map (fun entry => if entry.1 == node then (node, value) else entry)
      = entries := by
  induction entries with
  | nil => rfl
  | cons head tail ih =>
      have hhead := absent head (by simp)
      simp only [List.map_cons, beq_iff_eq, hhead, ite_false]
      rw [ih fun entry member => absent entry (by simp [member])]

private theorem map_set_self (entries : List (Node × LocalState)) (node : Node)
    (value : LocalState) (distinct : (entries.map Prod.fst).Nodup)
    (found : (entries.find? fun entry => entry.1 == node).map Prod.snd = some value)
    : entries.map (fun entry => if entry.1 == node then (node, value) else entry)
      = entries := by
  induction entries with
  | nil => simp at found
  | cons head tail ih =>
      simp only [List.map_cons, List.nodup_cons, List.mem_map] at distinct
      obtain ⟨fresh, distinct⟩ := distinct
      by_cases h : head.1 = node
      · simp only [List.find?_cons, h, beq_self_eq_true, Option.map_some,
          Option.some.injEq] at found
        simp only [List.map_cons, h, beq_self_eq_true, ite_true]
        rw [map_set_absent tail node value]
        · rw [← h, ← found]
        · intro entry member same
          exact fresh ⟨entry, member, by rw [same, h]⟩
      · have hne : (head.1 == node) = false := by simp [h]
        simp only [List.find?_cons, hne] at found
        simp only [List.map_cons, hne]
        rw [ih distinct found]
        rfl

/-- Overwriting a node with its current value changes nothing, given distinct keys. -/
theorem setNode_self {state : MultiNodeTransitionSystem.State Node LocalState Message}
    {node : Node} {value : LocalState} (distinct : (state.nodes.map Prod.fst).Nodup)
    (found : nodeState state node = some value)
    : setNode state node value = state := by
  cases state with
  | mk nodes network =>
      simp only [setNode, MultiNodeTransitionSystem.State.mk.injEq, and_true]
      exact map_set_self nodes node value distinct found

/-- Overwriting a node twice keeps the last value, whatever the network in between. -/
theorem setNode_network_setNode
    (state : MultiNodeTransitionSystem.State Node LocalState Message) (node : Node)
    (first second : LocalState) (network : List (Envelope Node Message))
    : setNode { setNode state node first with network } node second
      = { setNode state node second with network } := by
  simp only [setNode, List.map_map, MultiNodeTransitionSystem.State.mk.injEq, and_true]
  apply List.map_congr_left
  intro entry _
  by_cases h : entry.1 = node <;> simp [h]

end TableLemmas

section KeyedLists

variable {Node A B : Type}

theorem Keyed.keys {related : Node -> A -> B -> Prop}
    : forall {lefts : List (Node × A)} {rights : List (Node × B)},
        Keyed related lefts rights -> lefts.map Prod.fst = rights.map Prod.fst
  | [], [], _ => rfl
  | _ :: _, _ :: _, .cons _ rest => by simp [Keyed.keys rest]

variable [BEq Node] [LawfulBEq Node] in
theorem Keyed.find {related : Node -> A -> B -> Prop} {node : Node}
    : forall {lefts : List (Node × A)} {rights : List (Node × B)} {right : B},
        Keyed related lefts rights
        -> (rights.find? fun entry => entry.1 == node).map Prod.snd = some right
        -> exists left,
            (lefts.find? fun entry => entry.1 == node).map Prod.snd = some left
            /\ related node left right
  | [], [], _, _, found => by simp at found
  | (key, left) :: _, (_, _) :: _, right, .cons holds rest, found => by
      by_cases hkey : key = node
      · subst hkey
        simp only [List.find?_cons, beq_self_eq_true, Option.map_some, Option.some.injEq]
          at found ⊢
        subst found
        exact ⟨left, rfl, holds⟩
      · have hne : (key == node) = false := by simp [hkey]
        simp only [List.find?_cons, hne] at found ⊢
        exact Keyed.find rest found

variable [BEq Node] [LawfulBEq Node] in
theorem Keyed.set {related : Node -> A -> B -> Prop} {node : Node} {left : A} {right : B}
    (holds : related node left right)
    : forall {lefts : List (Node × A)} {rights : List (Node × B)},
        Keyed related lefts rights
        -> Keyed related
            (lefts.map fun entry => if entry.1 == node then (node, left) else entry)
            (rights.map fun entry => if entry.1 == node then (node, right) else entry)
  | [], [], _ => .nil
  | (key, _) :: _, (_, _) :: _, .cons holds' rest => by
      by_cases hkey : key = node
      · subst hkey
        simp only [List.map_cons, beq_self_eq_true, ite_true]
        exact .cons holds (Keyed.set holds rest)
      · have hne : (key == node) = false := by simp [hkey]
        simp only [List.map_cons, hne]
        exact .cons holds' (Keyed.set holds rest)

variable [BEq Node] [LawfulBEq Node] in
theorem Keyed.without {related : Node -> A -> B -> Prop} {node : Node}
    : forall {lefts : List (Node × A)} {rights : List (Node × B)},
        Keyed related lefts rights
        -> Keyed related (Sections.without lefts node) (Sections.without rights node)
  | [], [], _ => .nil
  | (key, _) :: _, (_, _) :: _, .cons holds rest => by
      by_cases hkey : key = node
      · subst hkey
        simpa [Sections.without] using Keyed.without (node := key) rest
      · have hne : (key == node) = false := by simp [hkey]
        have := Keyed.without (node := node) rest
        simp only [Sections.without, List.filter_cons, hne, Bool.not_false, ite_true] at this ⊢
        exact .cons holds this

theorem Keyed.map_flip {related : Node -> A -> B -> Prop} {C : Type}
    {other : Node -> C -> A -> Prop} {f : B -> C}
    (implies
      : forall node left right, related node left right -> other node (f right) left)
    : forall {lefts : List (Node × A)} {rights : List (Node × B)},
        Keyed related lefts rights
        -> Keyed other (rights.map fun entry => (entry.1, f entry.2)) lefts
  | [], [], _ => .nil
  | _ :: _, _ :: _, .cons holds rest =>
      .cons (implies _ _ _ holds) (Keyed.map_flip implies rest)

end KeyedLists

/-- Overwriting a node does not change the table without it. -/
theorem without_setNode {Node LocalState Message : Type} [BEq Node] [LawfulBEq Node]
    (state : MultiNodeTransitionSystem.State Node LocalState Message) (node : Node)
    (value : LocalState)
    : without (setNode state node value).nodes node = without state.nodes node := by
  simp only [without, setNode]
  induction state.nodes with
  | nil => rfl
  | cons head tail ih =>
      by_cases h : head.1 = node
      · simp [h, ih]
      · have hne : (head.1 == node) = false := by simp [h]
        simp only [List.map_cons, hne, Bool.false_eq_true, ite_false, List.filter_cons, ih]

section Machine

variable {Node Message LocalState Event : Type}
  {machine : Machine Node Message LocalState Event}
  {node : Node}

theorem Steps.snoc {start finish last : LocalState} {events : List Event} {event : Event}
    (steps : Steps machine node start events finish)
    (step : machine.step node finish none event = some last)
    : Steps machine node start (events ++ [event]) last := by
  induction steps with
  | nil => exact .cons step (.nil _)
  | cons first _ ih => exact .cons first (ih step)

theorem SectionRun.snoc {start finish last : LocalState}
    {received : Option (Node × Message)} {events : List Event} {event : Event}
    (run : SectionRun machine node start received events finish)
    (step : machine.step node finish none event = some last)
    : SectionRun machine node start received (events ++ [event]) last := by
  obtain ⟨first, rest, middle, rfl, hfirst, hsteps⟩ := run
  exact ⟨first, rest ++ [event], middle, by simp, hfirst, hsteps.snoc step⟩

theorem SectionRun.single {start finish : LocalState} {received : Option (Node × Message)}
    {event : Event} (step : machine.step node start received event = some finish)
    : SectionRun machine node start received [event] finish :=
  ⟨event, [], finish, rfl, step, .nil _⟩

end Machine

section Inversion

variable {Node Message LocalState Event : Type} [BEq Node] [BEq Message]
  {machine : Machine Node Message LocalState Event}
  {state after : State Node Message LocalState}

theorem next_event_inv {node : Node} {event : Event}
    (step : next machine state (.event node event) = some after)
    : exists slot current,
        nodeState state node = some slot
        /\ (!machine.opens event || slot.entry.isNone) = true
        /\ machine.step node slot.current none event = some current
        /\ after
            = setNode state node
                {
                  slot with
                    current, entry := slot.entry.orElse fun _ => some slot.current
                } := by
  simp only [next] at step
  cases found : nodeState state node with
  | none => simp [found] at step
  | some slot =>
      cases allowed : (!machine.opens event || slot.entry.isNone) with
      | false =>
          simp only [found, option_guard_bind, Option.bind_eq_bind, Option.bind_some] at step
          rw [allowed] at step
          simp at step
      | true =>
          cases ran : machine.step node slot.current none event with
          | none => simp [found, ran, option_guard_bind] at step
          | some current =>
              simp only [found, allowed, ran, option_guard_bind, Option.bind_eq_bind,
                Option.bind_some, ite_true, Option.pure_def, Option.some.injEq] at step
              exact ⟨slot, current, rfl, allowed, ran, step.symm⟩

theorem next_deliver_inv {envelope : Envelope Node Message} {event : Event}
    (step : next machine state (.deliver envelope event) = some after)
    : state.network.contains envelope = true
      /\ exists slot current,
          nodeState state envelope.target = some slot
          /\ slot.entry = none
          /\ machine.step envelope.target slot.current
                (some (envelope.source, envelope.payload)) event
              = some current
          /\ after
              = setNode state envelope.target
                  { current, entry := some slot.current, inbox := some envelope } := by
  simp only [next] at step
  cases queued : state.network.contains envelope with
  | false => simp [queued, option_guard_bind] at step
  | true =>
      cases found : nodeState state envelope.target with
      | none => simp [queued, found, option_guard_bind] at step
      | some slot =>
          cases free : slot.entry with
          | some _ => simp [queued, found, free, option_guard_bind] at step
          | none =>
              cases ran
                    : machine.step envelope.target slot.current
                        (some (envelope.source, envelope.payload)) event with
              | none => simp [queued, found, free, ran, option_guard_bind] at step
              | some current =>
                  simp only [queued, found, free, ran, option_guard_bind, Option.bind_eq_bind,
                    Option.bind_some, ite_true, Option.isNone_none, Option.pure_def,
                    Option.some.injEq] at step
                  exact ⟨rfl, slot, current, rfl, free, ran, step.symm⟩

theorem next_release_inv {node : Node}
    (step : next machine state (.release node) = some after)
    : exists slot start finish sends pending,
        nodeState state node = some slot
        /\ slot.entry = some start
        /\ machine.close
              ((without state.nodes node).map fun entry => (entry.1, entry.2.base)) node
              slot.current
            = some (finish, sends)
        /\ machine.idle finish = true
        /\ ((slot.inbox = none /\ pending = state.network)
            \/ exists envelope,
                slot.inbox = some envelope
                /\ state.network.contains envelope = true
                /\ pending = removeOne envelope state.network)
        /\ after
            = {
              setNode state node { current := finish } with
                network := pending ++ sends
            } := by
  simp only [next] at step
  cases found : nodeState state node with
  | none => simp [found] at step
  | some slot =>
      cases held : slot.entry with
      | none => simp [found, held, option_guard_bind] at step
      | some start =>
          cases closed
                : machine.close
                    ((without state.nodes node).map fun entry => (entry.1, entry.2.base))
                    node slot.current with
          | none => simp [found, held, closed, option_guard_bind] at step
          | some result =>
              obtain ⟨finish, sends⟩ := result
              cases hidle : machine.idle finish with
              | false => simp [found, held, closed, hidle, option_guard_bind] at step
              | true =>
                  cases hinbox : slot.inbox with
                  | none =>
                      simp only [found, held, closed, hidle, hinbox,
                        option_guard_bind, Option.bind_eq_bind, Option.bind_some,
                        Option.isSome_some, ite_true, Option.pure_def,
                        Option.some.injEq] at step
                      exact ⟨slot, start, finish, sends, state.network, rfl, held, closed, hidle,
                        .inl ⟨hinbox, rfl⟩, step.symm⟩
                  | some envelope =>
                      cases queued : state.network.contains envelope with
                      | false =>
                          simp [found, held, closed, hinbox, queued, option_guard_bind] at step
                      | true =>
                          simp only [found, held, closed, hidle, hinbox, queued,
                            option_guard_bind, Option.bind_eq_bind, Option.bind_some,
                            Option.isSome_some, ite_true, Option.pure_def,
                            Option.some.injEq] at step
                          exact ⟨slot, start, finish, sends, removeOne envelope state.network,
                            rfl, held, closed, hidle,
                            .inr ⟨envelope, hinbox, queued, rfl⟩, step.symm⟩

end Inversion

section Lift

variable {Node Message CleanState LocalAction Notification Input : Type}
  [BEq Node] [BEq Message]

/-- One clean internal step through the network composition. -/
theorem next_local
    (protocol
      : MultiNodeTransitionSystem.Protocol Node CleanState LocalAction Message
          Notification Input)
    {state : MultiNodeTransitionSystem.State Node CleanState Message} {node : Node}
    {before after : CleanState} {input : Input}
    {effects : Outputs Node Message Notification}
    (found : nodeState state node = some before)
    (step
      : (protocol.step (Capabilities.record node) node before
          (protocol.internal input)).run
          {}
        = some (after, effects))
    : MultiNodeTransitionSystem.next protocol state (.local node input)
      = some
          {
            setNode state node after with
              network := state.network ++ effects.outgoing
          } := by
  simp [MultiNodeTransitionSystem.next, found, step, setNode]

/-- One clean delivery through the network composition. -/
theorem next_deliver
    (protocol
      : MultiNodeTransitionSystem.Protocol Node CleanState LocalAction Message
          Notification Input)
    {state : MultiNodeTransitionSystem.State Node CleanState Message}
    {envelope : Envelope Node Message} {before after : CleanState}
    {effects : Outputs Node Message Notification}
    (queued : state.network.contains envelope = true)
    (found : nodeState state envelope.target = some before)
    (step
      : (protocol.step (Capabilities.record envelope.target) envelope.target before
          (protocol.receive envelope.source envelope.payload)).run
          {}
        = some (after, effects))
    : MultiNodeTransitionSystem.next protocol state (.deliver envelope)
      = some
          {
            setNode state envelope.target after with
              network := removeOne envelope state.network ++ effects.outgoing
          } := by
  simp [MultiNodeTransitionSystem.next, queued, found, step, setNode, option_guard_bind]

variable [LawfulBEq Node]

/-- Admitted clean internal local steps lift to a guarded network run touching one node. -/
theorem localRun_lift
    (protocol
      : MultiNodeTransitionSystem.Protocol Node CleanState LocalAction Message
          Notification Input)
    (admit : List (Node × CleanState) -> Node -> Input -> Bool)
    {node : Node} {others : List (Node × CleanState)}
    : forall {start finish : CleanState} {inputs : List Input}
              {sends : List (Envelope Node Message)},
        LocalRun protocol node start (inputs.map protocol.internal) finish sends
        -> (forall input, input ∈ inputs -> admit others node input = true)
        -> forall (state : MultiNodeTransitionSystem.State Node CleanState Message),
            (state.nodes.map Prod.fst).Nodup
            -> nodeState state node = some start
            -> without state.nodes node = others
            -> Run (guarded protocol admit) state (inputs.map (.local node))
                { setNode state node finish with network := state.network ++ sends }
  | _, _, [], _, run, _, state, distinct, found, _ => by
      cases run
      rw [setNode_self distinct found]
      have : ({ state with network := state.network ++ [] }
          : MultiNodeTransitionSystem.State Node CleanState Message) = state := by
        cases state; simp
      rw [this]
      exact .nil _
  | _, _, input :: inputs, _, run, admitted, state, distinct, found, rest => by
      cases run with
      | cons step tail =>
          rename_i middle effects sends
          have first
              : (guarded protocol admit).step state (.local node input)
                = some { setNode state node middle with
                    network := state.network ++ effects.outgoing } := by
            show guardedNext protocol admit state (.local node input) = _
            simp only [guardedNext, rest, admitted input (by simp), ite_true]
            exact next_local protocol found step
          refine .cons first ?_
          have := localRun_lift protocol admit tail
            (fun input' member => admitted input' (by simp [member]))
            { setNode state node middle with network := state.network ++ effects.outgoing }
            (by rw [keys_setNode]; exact distinct)
            (nodeState_setNode found)
            (by rw [← rest]; exact without_setNode state node middle)
          simp only [setNode_network_setNode, List.append_assoc] at this
          exact this

end Lift

section Simulation

variable {Node Message LocalState Event CleanState LocalAction Notification Input : Type}
  {machine : Machine Node Message LocalState Event}

/-- The section bookkeeping invariant of one node's slot. -/
def SlotInv (machine : Machine Node Message LocalState Event) (node : Node)
    (slot : Slot Node Message LocalState)
    : Prop :=
  match slot.entry with
  | none => slot.inbox = none /\ machine.idle slot.current = true
  | some start =>
      machine.idle start = true
      /\ (forall envelope, slot.inbox = some envelope -> envelope.target = node)
      /\ exists events,
          SectionRun machine node start
            (slot.inbox.map fun envelope => (envelope.source, envelope.payload))
            events slot.current

/--
A clean state simulates an event-granular state: equal networks whose messages satisfy
`msgInv`, distinct nodes, and
each node's clean state related to its slot's abstracted local state.
-/
def Sim (machine : Machine Node Message LocalState Event)
    (rel : Node -> CleanState -> LocalState -> Prop)
    (msgInv : Envelope Node Message -> Prop)
    (clean : MultiNodeTransitionSystem.State Node CleanState Message)
    (state : State Node Message LocalState)
    : Prop :=
  (clean.network = state.network
    /\ forall envelope, envelope ∈ state.network -> msgInv envelope)
  /\ (state.nodes.map Prod.fst).Nodup
  /\ Keyed
      (fun node cleanLocal slot =>
        rel node cleanLocal slot.base /\ SlotInv machine node slot)
      clean.nodes state.nodes

variable {rel : Node -> CleanState -> LocalState -> Prop}
  {msgInv : Envelope Node Message -> Prop}

theorem Sim.lookup [BEq Node] [LawfulBEq Node]
    {clean : MultiNodeTransitionSystem.State Node CleanState Message}
    {state : State Node Message LocalState} {node : Node}
    {slot : Slot Node Message LocalState} (sim : Sim machine rel msgInv clean state)
    (found : nodeState state node = some slot)
    : exists cleanLocal,
        nodeState clean node = some cleanLocal
        /\ rel node cleanLocal slot.base
        /\ SlotInv machine node slot :=
  let ⟨cleanLocal, cleanFound, holds⟩ := sim.2.2.find found
  ⟨cleanLocal, cleanFound, holds⟩

theorem Sim.cleanDistinct
    {clean : MultiNodeTransitionSystem.State Node CleanState Message}
    {state : State Node Message LocalState} (sim : Sim machine rel msgInv clean state)
    : (clean.nodes.map Prod.fst).Nodup := by
  rw [sim.2.2.keys]; exact sim.2.1

theorem Sim.set [BEq Node] [LawfulBEq Node]
    {clean : MultiNodeTransitionSystem.State Node CleanState Message}
    {state : State Node Message LocalState} {node : Node} {cleanLocal : CleanState}
    {slot : Slot Node Message LocalState} (sim : Sim machine rel msgInv clean state)
    (found : nodeState clean node = some cleanLocal)
    (related : rel node cleanLocal slot.base) (holds : SlotInv machine node slot)
    : Sim machine rel msgInv clean (setNode state node slot) := by
  refine ⟨sim.1, by rw [keys_setNode]; exact sim.2.1, ?_⟩
  have := sim.2.2.set (node := node) (left := cleanLocal) (right := slot) ⟨related, holds⟩
  have same := setNode_self sim.cleanDistinct found
  rw [← same]
  exact this

/-- Event steps keep the simulation with the same clean state. -/
theorem event_sim [BEq Node] [BEq Message] [LawfulBEq Node]
    {clean : MultiNodeTransitionSystem.State Node CleanState Message}
    {state after : State Node Message LocalState} {node : Node} {event : Event}
    (sim : Sim machine rel msgInv clean state)
    (step : next machine state (.event node event) = some after)
    : Sim machine rel msgInv clean after := by
  obtain ⟨slot, current, found, _, ran, rfl⟩ := next_event_inv step
  obtain ⟨cleanLocal, cleanFound, related, holds⟩ := sim.lookup found
  obtain ⟨current0, entry0, inbox0⟩ := slot
  refine sim.set cleanFound ?_ ?_
  · cases entry0 <;> simpa [Slot.base] using related
  · cases entry0 with
    | none =>
        obtain ⟨hinbox, hidle⟩ := holds
        simp only at hinbox
        subst hinbox
        exact ⟨hidle, by simp, [event], by simpa using SectionRun.single ran⟩
    | some start =>
        obtain ⟨hidle, htarget, events, hrun⟩ := holds
        exact ⟨hidle, htarget, events ++ [event], hrun.snoc ran⟩

/-- Delivery steps keep the simulation with the same clean state. -/
theorem deliver_sim [BEq Node] [BEq Message] [LawfulBEq Node]
    {clean : MultiNodeTransitionSystem.State Node CleanState Message}
    {state after : State Node Message LocalState} {envelope : Envelope Node Message}
    {event : Event} (sim : Sim machine rel msgInv clean state)
    (step : next machine state (.deliver envelope event) = some after)
    : Sim machine rel msgInv clean after := by
  obtain ⟨_, slot, current, found, free, ran, rfl⟩ := next_deliver_inv step
  obtain ⟨cleanLocal, cleanFound, related, holds⟩ := sim.lookup found
  obtain ⟨current0, entry0, inbox0⟩ := slot
  simp only at free
  subst free
  obtain ⟨_, hidle⟩ := holds
  refine sim.set cleanFound (by simpa [Slot.base] using related) ?_
  exact ⟨hidle, by simp, [event], by simpa using SectionRun.single ran⟩

/-- Initial event-granular states are simulated by initial clean states over the same nodes. -/
theorem init_sim
    {protocol
      : MultiNodeTransitionSystem.Protocol Node CleanState LocalAction Message
          Notification Input}
    {admit : List (Node × CleanState) -> Node -> Input -> Bool}
    (refinement : Refinement machine protocol admit)
    : forall (nodes : List (Node × Slot Node Message LocalState)),
        (forall entry,
          entry ∈ nodes
          -> entry.2.entry = none
              /\ entry.2.inbox = none
              /\ machine.init entry.1 entry.2.current)
        -> exists cleanNodes : List (Node × CleanState),
            Keyed
              (fun node cleanLocal slot =>
                refinement.rel node cleanLocal slot.base /\ SlotInv machine node slot)
              cleanNodes nodes
            /\ forall entry, entry ∈ cleanNodes -> protocol.init entry.1 entry.2
  | [], _ => ⟨[], .nil, by simp⟩
  | (node, slot) :: rest, initial => by
      obtain ⟨cleanRest, keyed, inits⟩ :=
        init_sim refinement rest fun entry member => initial entry (by simp [member])
      obtain ⟨free, empty, hinit⟩ := initial (node, slot) (by simp)
      obtain ⟨hidle, cleanLocal, cleanInit, related⟩ := refinement.init_sound node _ hinit
      refine ⟨(node, cleanLocal) :: cleanRest, .cons ⟨?_, ?_⟩ keyed, ?_⟩
      · have free' : slot.entry = none := free
        simp only [Slot.base, free', Option.getD_none]; exact related
      · have free' : slot.entry = none := free
        unfold SlotInv; rw [free']; exact ⟨empty, hidle⟩
      · intro entry member
        simp only [List.mem_cons] at member
        rcases member with rfl | member
        · exact cleanInit
        · exact inits entry member

theorem Sim.release [BEq Node] [LawfulBEq Node]
    {clean : MultiNodeTransitionSystem.State Node CleanState Message}
    {state : State Node Message LocalState} {node : Node} {cleanFinish : CleanState}
    {finish : LocalState} (pending sends : List (Envelope Node Message))
    (sim : Sim machine rel msgInv clean state) (related : rel node cleanFinish finish)
    (idle : machine.idle finish = true)
    (valid : forall envelope, envelope ∈ pending ++ sends -> msgInv envelope)
    : Sim machine rel msgInv
        { setNode clean node cleanFinish with network := pending ++ sends }
        {
          setNode state node { current := finish } with
            network := pending ++ sends
        } := by
  refine ⟨⟨rfl, valid⟩, ?_, ?_⟩
  · show ((setNode state node { current := finish }).nodes.map Prod.fst).Nodup
    rw [keys_setNode]; exact sim.2.1
  · show Keyed _ (setNode clean node cleanFinish).nodes (setNode state node { current := finish }).nodes
    exact sim.2.2.set (left := cleanFinish) (right := { current := finish })
      ⟨related, ⟨rfl, idle⟩⟩

theorem mem_of_mem_removeOne {α : Type _} [BEq α] {value item : α}
    : forall {items : List α}, item ∈ removeOne value items -> item ∈ items
  | [], member => member
  | head :: tail, member => by
      unfold removeOne at member
      split at member
      · exact List.mem_cons_of_mem _ member
      · simp only [List.mem_cons] at member ⊢
        rcases member with rfl | member
        · exact Or.inl rfl
        · exact Or.inr (mem_of_mem_removeOne member)

/-- A release is matched by the section's clean local run, keeping the simulation. -/
theorem release_sim [BEq Node] [BEq Message] [LawfulBEq Node] [LawfulBEq Message]
    {protocol
      : MultiNodeTransitionSystem.Protocol Node CleanState LocalAction Message
          Notification Input}
    {admit : List (Node × CleanState) -> Node -> Input -> Bool}
    (refinement : Refinement machine protocol admit)
    {clean : MultiNodeTransitionSystem.State Node CleanState Message}
    {state after : State Node Message LocalState} {node : Node}
    (sim : Sim machine refinement.rel refinement.msgInv clean state)
    (step : next machine state (.release node) = some after)
    : exists chunk clean',
        Run (guarded protocol admit) clean chunk clean'
        /\ Sim machine refinement.rel refinement.msgInv clean' after := by
  obtain ⟨slot, start, finish, sends, pending, found, held, closed, hidle, hinbox, rfl⟩ :=
    next_release_inv step
  obtain ⟨cleanLocal, cleanFound, related, holds⟩ := sim.lookup found
  obtain ⟨current0, entry0, inbox0⟩ := slot
  simp only at held
  subst held
  obtain ⟨hstart, htarget, events, hrun⟩ := holds
  have relStart : refinement.rel node cleanLocal start := related
  have others := (sim.2.2.without (node := node)).map_flip (f := Slot.base)
    (other := fun other local_ cleanOther => refinement.rel other cleanOther local_)
    (fun _ _ _ holds => holds.1)
  have received : forall source message,
      (inbox0.map fun envelope => (envelope.source, envelope.payload)) = some (source, message)
      -> refinement.msgInv ⟨source, node, message⟩ := by
    intro source message hsome
    rcases hinbox with ⟨hnone, _⟩ | ⟨envelope, hin, queued, _⟩
    · simp only at hnone; subst hnone; simp at hsome
    · simp only at hin; subst hin
      simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hsome
      obtain ⟨rfl, rfl⟩ := hsome
      have target := htarget envelope rfl
      obtain ⟨source, target', payload⟩ := envelope
      simp only at target
      subst target
      exact sim.1.2 _ (List.contains_iff_mem.mp queued)
  obtain ⟨inputs, cleanFinish, localRun, relFinish, admitted, sent⟩ :=
    refinement.section_sound node start _ events current0 finish sends cleanLocal _ _ hstart
      relStart received hrun closed hidle others
  have distinct := sim.cleanDistinct
  have valid : forall pending, (forall envelope, envelope ∈ pending -> envelope ∈ state.network)
      -> forall envelope, envelope ∈ pending ++ sends -> refinement.msgInv envelope := by
    intro pending sub envelope member
    rcases List.mem_append.mp member with member | member
    · exact sim.1.2 _ (sub _ member)
    · exact sent _ member
  rcases hinbox with ⟨hnone, rfl⟩ | ⟨envelope, hsome, queued, rfl⟩
  · simp only at hnone
    subst hnone
    simp only [Option.map_none, Option.toList_none, List.nil_append] at localRun
    refine ⟨inputs.map (.local node), _, ?_, sim.release state.network sends relFinish hidle
      (valid _ fun _ member => member)⟩
    have := localRun_lift protocol admit localRun admitted clean distinct cleanFound rfl
    rw [sim.1.1] at this
    exact this
  · simp only at hsome
    subst hsome
    have htgt : envelope.target = node := htarget envelope rfl
    subst htgt
    simp only [Option.map_some, Option.toList_some, List.singleton_append] at localRun
    cases localRun with
    | cons first rest =>
        rename_i middle effects restSends
        refine ⟨.deliver envelope :: inputs.map (.local envelope.target), _, ?_,
          sim.release (removeOne envelope state.network) _ relFinish hidle
            (valid _ fun _ member => mem_of_mem_removeOne member)⟩
        have hqueued : clean.network.contains envelope = true := by rw [sim.1.1]; exact queued
        refine .cons (show guardedNext protocol admit clean (.deliver envelope) = _ from
          next_deliver protocol hqueued cleanFound first) ?_
        have := localRun_lift protocol admit rest admitted
          { setNode clean envelope.target middle with
              network := removeOne envelope clean.network ++ effects.outgoing }
          (by show ((setNode clean envelope.target middle).nodes.map Prod.fst).Nodup
              rw [keys_setNode]; exact distinct)
          (nodeState_setNode cleanFound)
          (without_setNode clean envelope.target middle)
        simp only [setNode_network_setNode, List.append_assoc] at this
        rw [← sim.1.1]
        exact this

end Simulation
