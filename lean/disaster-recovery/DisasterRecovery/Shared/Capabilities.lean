import Std

namespace DisasterRecovery.Shared

abbrev Effect (Node Message : Type) := StateM (List (Node × Message))

structure Capabilities (Node Message : Type) where
  send : Message -> Node -> Effect Node Message Unit

end DisasterRecovery.Shared
