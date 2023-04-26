import "@typespec/http"; // for TypeSpec.Http.[route|query]
import "@azure-tools/typespec-azure-core"; // for Azure.Core.RpcOperation

alias TxIdRegex = "^[0-9]+\\.[0-9]+$";

@doc("Possible states for a CCF transaction. See docs for details: https://microsoft.github.io/CCF/main/use_apps/verify_tx.html#checking-for-commit")
enum TxStatus {
  Unknown,
  Pending,
  Committed,
  Invalid,
}

@doc("Description of a transaction's current state.")
model TxInfo {
  @doc("Status of this transaction.")
  status: TxStatus;

  @doc("Identifier of this transaction, containing view and sequence number.")
  @pattern(TxIdRegex)
  @visibility("read")
  transactionId: string;
}

@doc("Description of the latest committed transaction on the service.")
model CommitInfo {
  @doc("Identifier of latest committed transaction.")
  @pattern(TxIdRegex)
  @visibility("read")
  transactionId: string;
}

interface Transactions {
  @doc("Fetch status of transaction by transaction ID, to determine whether it has committed.")
  @TypeSpec.Http.route("tx")
  getTransactionInfo is Azure.Core.RpcOperation<
    {
      @doc("Identifier for target transaction.")
      @TypeSpec.Http.query
      transactionId: string;
    },
    TxInfo
  >;

  @doc("Get current committed sequence number. May be used to poll for a specific transaction to be committed, or to verify that all nodes are in-sync.")
  @TypeSpec.Http.route("commit")
  getCommit is Azure.Core.RpcOperation<{}, CommitInfo>;
}
