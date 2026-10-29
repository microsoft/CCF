module

public import CCFRaft.Properties.Liveness.Model.Event
public import CCFRaft.Properties.Liveness.Model.Trace
public import CCFRaft.Properties.Liveness.Model.World

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

/-- Crash-stop availability after an event. -/
def Event.liveAfter (event : Event) (live : Finset NodeID) : Finset NodeID :=
  match event with
  | .crash node => live.erase node
  | _ => live

/-- Actors must be live, and crashes permanently remove them.
The initial live set is unrestricted. -/
abbrev crashSystem : CCF.TransitionSystem where
  State := Finset NodeID
  Action := Event
  init _ := True
  step live event :=
    match event.actor with
    | some node =>
        if node ∈ live then
          some
            (match event with
              | .crash _ => live.erase node
              | _ => live)
        else
          none
    | none => some (event.liveAfter live)

/-- Constrain only availability, directly using the crash-stop system. -/
def crashModel {W : Type} [HasLive W] : Model W Event where
  init world := crashSystem.init (HasLive.live world)
  next step :=
    crashSystem.step (HasLive.live step.before) step.action
    = some (HasLive.live step.after)

end CCFRaft.Liveness
