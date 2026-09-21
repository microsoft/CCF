import Std

namespace DisasterRecovery.Shared

structure Capabilities (σ Node Message : Type) where
  send : Message -> Node -> ST σ Unit

end DisasterRecovery.Shared
