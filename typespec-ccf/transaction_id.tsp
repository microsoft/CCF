import "@typespec/http";
import "@azure-tools/typespec-azure-core";

alias TxIdRegex = "^[0-9]+\\.[0-9]+$";
alias TxIdHeaderField = "x-ms-ccf-transaction-id";

alias TxIdWriteHeader = Azure.Core.Traits.RequestHeadersTrait<{
  @doc("Identifier for transaction where this request produced a write on the service. This uniquely identifies the submitted request, and can be used to confirm that the request becomes committed.")
  @TypeSpec.Http.header(TxIdHeaderField)
  @pattern(TxIdRegex)
  transactionId: string;
}>;

alias TxIdReadHeader = Azure.Core.Traits.RequestHeadersTrait<{
  @doc("Identifier for transaction this response was read from. The service state may be altered by other write requests. Reads at the same transactionId describe a consistent single point in the service history.")
  @TypeSpec.Http.header(TxIdHeaderField)
  @pattern(TxIdRegex)
  transactionId: string;
}>;
