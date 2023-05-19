import "@typespec/rest";
import "@azure-tools/typespec-azure-core";

import "./common.tsp";

@doc("TODO")
@TypeSpec.Rest.resource("encrypted-recovery-shares")
model EncryptedRecoveryShare {
  @doc("ID of CCF member who this recovery share belongs to.")
  @visibility("read")
  @key
  memberId: memberId;
}

@doc("TODO")
model RecoveryShare {
  @doc("TODO")
  share: string;
}

@doc("Response to a submitted recovery share.")
model RecoveryResponse {
  @doc("Human-readable description of current recovery progress.")
  message: string;

  @doc("Count of how many accepted member shares have been submitted, including the current request.")
  submittedCount: uint64;

  @doc("Count of how many member shares are required to initiate the end-of-recovery procedure.")
  recoveryThreshold: uint64;
}

@doc("TODO")
@TypeSpec.Rest.resource("members")
model Member {
  @doc("TODO")
  @visibility("read")
  @key
  memberId: memberId;
}

interface Recovery {
  @doc("A member's recovery share, encrypted with that member's share-encryption key.")
  getEncryptedShare is Azure.Core.StandardResourceOperations.ResourceRead<EncryptedRecoveryShare>;

  @doc("Provide a recovery share for the purpose of completing a service recovery.")
  @TypeSpec.Rest.action("recover")
  submitRecoveryShare is Azure.Core.StandardResourceOperations.ResourceAction<
    Member,
    RecoveryShare,
    RecoveryResponse,
    TxIdReadHeader
  >;
}
