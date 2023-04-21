import "@typespec/rest";
import "@typespec/versioning";
import "@azure-tools/typespec-azure-core";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;
using Azure.Core;
using Azure.Core.Traits;

@service({
  title: "Managed CCF Governance",
})
@versioned(Microsoft.ManagedCcf.Versions)
namespace Microsoft.ManagedCcf;

enum Versions {
  @useDependency(Azure.Core.Versions.v1_0_Preview_1)
  `2023-04-20-preview`,
}

@doc("Possible states for a CCF transaction. See docs for details: https://microsoft.github.io/CCF/main/use_apps/verify_tx.html#checking-for-commit")
enum TxStatus {
  "Unknown",
  "Pending",
  "Committed",
  "Invalid",
}

@doc("Description of a transaction")
@resource("tx")
model TxInfo {
  @doc("Status of this transaction")
  status : TxStatus;

  @doc("Identifier of this transaction, containing view and sequence number")
  @pattern("^[0-9]+\\.[0-9]+$")
  @key("transactionId")
  @visibility("read")
  transactionId: string;
}

@route("/foo")
interface Gov
{
  @doc("Fetch status of transaction by transaction ID, to determine whether it has committed.")
  @route("/bar")
  @get getTx(): {}
}


@doc("A widget.")
@resource("widgets")
model Widget {
  @key("widgetName")
  @doc("The widget name.")
  @visibility("read")
  name: string;

  @doc("The ID of the manufacturer.")
  manufacturerId: string;
}

interface Widgets {
  @doc("Fetch a Widget by name.")
  getWidget is ResourceRead<Widget>;

  //@doc("Gets status of a Widget operation.")
  //getWidgetOperationStatus is GetResourceOperationStatus<Widget>;

  //@doc("Creates or updates a Widget asynchronously.")
  //@pollingOperation(Widgets.getWidgetOperationStatus)
  //createOrUpdateWidget is LongRunningResourceCreateOrUpdate<Widget>;

  //@doc("Delete a Widget asynchronously.")
  //@pollingOperation(Widgets.getWidgetOperationStatus)
  //deleteWidget is LongRunningResourceDelete<Widget>;

  @doc("List Widget resources")
  listWidgets is ResourceList<
    Widget,
    {
      parameters: StandardListQueryParameters;
    }
  >;
}
