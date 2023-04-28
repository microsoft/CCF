import "@typespec/http";
import "@typespec/rest";
import "@azure-tools/typespec-azure-core";

import "./transaction_id.tsp";

@doc("Possible states for a CCF transaction. See docs for details: https://microsoft.github.io/CCF/main/use_apps/verify_tx.html#checking-for-commit")
enum TransactionStatus {
  Unknown,
  Pending,
  Committed,
  Invalid,
}

@doc("Description of a transaction's current state.")
@TypeSpec.Rest.resource("transactions")
model Transaction {
  @doc("Status of this transaction.")
  status: TransactionStatus;

  @doc("Identifier of this transaction, containing view and sequence number.")
  @pattern(TxIdRegex)
  @visibility("read")
  @key
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
  @doc("Get status of transaction by transaction ID, to determine whether it has committed.")
  @TypeSpec.Rest.action("status")
  @TypeSpec.Rest.actionSeparator("/")
  @TypeSpec.Http.get
  getTransactionStatus is Azure.Core.StandardResourceOperations.ResourceAction<
    Transaction,
    {},
    Transaction
  >;

  @doc("Get latest committed transaction.")
  @TypeSpec.Rest.action("commit")
  @TypeSpec.Rest.actionSeparator("/")
  @TypeSpec.Http.get
  getCommit is Azure.Core.StandardResourceOperations.ResourceCollectionAction<
    Transaction,
    {},
    Transaction
  >;

  // To add:
  // - /transactions/{transactionId}/receipt (Long-running)
}
