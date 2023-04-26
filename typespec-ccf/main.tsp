import "@typespec/http";
import "@typespec/rest";
import "@typespec/versioning";
import "@azure-tools/typespec-azure-core";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;
using Azure.Core;
using Azure.Core.Traits;

@service({
  title: "Contoso Widget Manager",
})
@versioned(Contoso.WidgetManager.Versions)
namespace Contoso.WidgetManager;

enum Versions {
  @useDependency(Azure.Core.Versions.v1_0_Preview_2)
  `2022-08-31`,
}

// Models ////////////////////

@doc("The color of a widget.")
enum WidgetColor {
  Black,
  White,
  Red,
  Green,
  Blue,
}

@doc("A widget.")
@resource("widgets")
model Widget {
  @key("widgetName")
  @doc("The widget name.")
  @visibility("read")
  name: string;

  @doc("The widget color.")
  color: WidgetColor;

  @doc("The ID of the widget's manufacturer.")
  manufacturerId: string;
  ...EtagProperty;
}

@doc("The repair state of a widget.")
@lroStatus
enum WidgetRepairState {
  Succeeded,
  Failed,
  Canceled,
  SentToManufacturer,
}

@doc("A submitted repair request for a widget.")
model WidgetRepairRequest {
  @doc("The state of the widget repair request.")
  requestState: WidgetRepairState;

  @doc("The date and time when the repair is scheduled to occur.")
  scheduledDateTime: utcDateTime;

  @doc("The date and time when the request was created.")
  createdDateTime: utcDateTime;

  @doc("The date and time when the request was updated.")
  updatedDateTime: utcDateTime;

  @doc("The date and time when the request was completed.")
  completedDateTime: utcDateTime;
}

@doc("The parameters for a widget status request")
model WidgetRepairStatusParams {
  @doc("The ID of the widget being repaired.")
  @path
  widgetId: string;
}

@doc("A widget's part.")
@resource("parts")
@parentResource(Widget)
model WidgetPart {
  @key("widgetPartName")
  @doc("The name of the part.")
  @visibility("read")
  name: string;

  @doc("The ID to use for reordering the part.")
  partId: string;

  @doc("The ID of the part's manufacturer.")
  manufacturerId: string;
  ...EtagProperty;
}

@doc("The details of a reorder request for a WidgetPart.")
model WidgetPartReorderRequest {
  @doc("Identifies who signed off the reorder request.")
  signedOffBy: string;
}

// An example of a singleton resource
@doc("Provides analytics about the use and maintenance of a Widget.")
@resource("analytics")
@parentResource(Widget)
model WidgetAnalytics {
  @key("analyticsId")
  @doc("The identifier for the analytics object.  There is only one named 'current'.")
  @visibility("read")
  id: "current";

  @doc("The number of uses of the widget.")
  useCount: int64;

  @doc("The number of times the widget was repaired.")
  repairCount: int64;
}

@doc("A manufacturer of widgets.")
@resource("manufacturers")
model Manufacturer {
  @key("manufacturerId")
  @doc("The manufacturer's unique ID.")
  @visibility("read")
  id: string;

  @doc("The manufacturer's name.")
  name: string;

  @doc("The manufacturer's full address.")
  address: string;
  ...EtagProperty;
}

// Operations ////////////////////

alias ServiceTraits = SupportsRepeatableRequests &
  SupportsConditionalRequests &
  SupportsClientRequestId;

enum NodeStatus {
    "Pending",
    "Trusted",
    "Retired"
}

interface Widgets {
  // Operation Status
  @doc("Gets status of a Widget operation.")
  getWidgetOperationStatus is Operations.GetResourceOperationStatus<Widget>;

  // Widget Operations
  @doc("Creates or updates a Widget asynchronously")
  @pollingOperation(Widgets.getWidgetOperationStatus)
  createOrUpdateWidget is Operations.LongRunningResourceCreateOrUpdate<Widget>;

  @doc("Get a Widget")
  getWidget is Operations.ResourceRead<Widget>;

  @doc("Delete a Widget asynchronously.")
  @pollingOperation(Widgets.getWidgetOperationStatus)
  deleteWidget is Operations.LongRunningResourceDelete<Widget>;

  @doc("List Widget resources")
  listWidgets is Operations.ResourceList<
    Widget,
    ListQueryParametersTrait<StandardListQueryParameters & SelectQueryParameter>
  >;

  // Widget Analytics
  @doc("Get a WidgetAnalytics")
  getAnalytics is Operations.ResourceRead<WidgetAnalytics>;

  @doc("Creates or updates a WidgetAnalytics")
  updateAnalytics is Operations.ResourceCreateOrUpdate<WidgetAnalytics>;

  // Widget Repair Operations
  #suppress "@azure-tools/typespec-azure-core/use-standard-operations" "This is a custom operation status endpoint."
  @doc("Get the status of a WidgetRepairRequest.")
  @route("/widgets/{widgetId}/repairs/{operationId}")
  getRepairStatus is Foundations.GetOperationStatus<WidgetRepairStatusParams, WidgetRepairRequest>;

  @doc("Schedule a widget for repairs.")
  @pollingOperation(Widgets.getWidgetOperationStatus)
  scheduleRepairs is Operations.ResourceAction<
    Widget,
    WidgetRepairRequest,
    WidgetRepairRequest & RequestIdResponseHeader
  >;
}

interface WidgetParts {
  @doc("Gets status of a WidgetPart operation.")
  getWidgetPartOperationStatus is Operations.GetResourceOperationStatus<WidgetPart>;

  @doc("Creates a WidgetPart")
  createWidgetPart is Operations.ResourceCreateWithServiceProvidedName<WidgetPart>;

  @doc("Get a WidgetPart")
  getWidgetPart is Operations.ResourceRead<WidgetPart>;

  @doc("Delete a WidgetPart")
  deleteWidgetPart is Operations.ResourceDelete<WidgetPart>;

  @doc("List WidgetPart resources")
  listWidgetParts is Operations.ResourceList<WidgetPart>;

  @doc("Reorder all parts for the widget.")
  @pollingOperation(WidgetParts.getWidgetPartOperationStatus)
  reorderParts is Operations.LongRunningResourceCollectionAction<
    WidgetPart,
    WidgetPartReorderRequest,
    TypeSpec.Http.AcceptedResponse
  >;
}

interface Manufacturers {
  @doc("Gets status of a Manufacturer operation.")
  getManufacturerOperationStatus is Operations.GetResourceOperationStatus<Manufacturer>;

  @doc("Creates or replaces a Manufacturer")
  createManufacturer is Operations.ResourceCreateOrReplace<Manufacturer>;

  @doc("Get a Manufacturer")
  getManufacturer is Operations.ResourceRead<Manufacturer>;

  @doc("Delete a Manufacturer asynchronously.")
  @pollingOperation(Manufacturers.getManufacturerOperationStatus)
  deleteManufacturer is Operations.LongRunningResourceDelete<Manufacturer>;

@route("/gov/ack")
@summary("Provide a member endorsement of a service state digest")
@post op ack(@body state_digest: StateDigest): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @statusCode statusCode: 204;
};

@route("/gov/ack/update_state_digest")
@summary("Update and fetch a service state digest, for the purpose of member endorsement")
@post op updateStateDigest(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body stateDigest: StateDigest;
};

@route("/gov/commit")
@doc("Latest transaction ID that has been committed on the service")
@summary("Current commit level")
@get op commit(@query view_history?: boolean, @query view_history_since?: int64): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body govCommit: GetCommit;
};

@route("/gov/kv/constitution")
@get op getConstitution(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body constitution: string;
};

// TODO: @extension("x-ccf-forwarding", true), @defaultresponse -- decorators don't work
@route("/gov/kv/cose_history")
@get op getCoseHistory(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body coseHistory: StringToBase64;
};

@route("/gov/kv/cose_recent_proposals")
@get op getCoseRecentProposals(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body coseRecentProposals: string;
};

@route("/gov/kv/history")
@get op getHistory(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body history: MemberIdToSignedReq;
};

@route("/gov/kv/js_runtime_options")
@get op getJSRuntimeOptions(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body jsRuntimeOptions: JSRuntimeOptions;
};

@route("/gov/kv/jwt/issuers")
@get op getJwtIssuers(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body jwtIssuers: StringToJwtIssuerMetadata;
};

@route("/gov/kv/jwt/public_signing_key_issuer")
@get op getJwtPublicSigningKeyIssuer(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body jwtPublicSigningKeyIssuer: string;
};

@route("/gov/kv/jwt/public_signing_keys")
@get op getJwtPublicSigningKeys(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body jwtPublicSigningKeys: StringToBase64;
};

@route("/gov/kv/members/acks")
@get op getMembersAcks(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body membersAcks: MemberIdToMemberAck;
};

@route("/gov/kv/members/certs")
@get op getMembersCerts(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body membersCerts: MemberIdToPem;
};

@route("/gov/kv/members/encryption_public_keys")
@get op getMembersEncryptionPublicKeys(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body membersEncryptionPublicKeys: MemberIdToPem;
};

@route("/gov/kv/members/info")
@get op getMembersInfo(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body membersInfo: MemberIdToMemberDetails;
};

@route("/gov/kv/modules")
@get op getModules(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body modules: string;
};

@route("/gov/kv/modules_quickjs_bytecode")
@get op getModulesQuickJSBytecode(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body modulesQuickJSBytecode: StringToBase64;
};

@route("/gov/kv/modules_quickjs_version")
@get op getModulesQuickJSVersion(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body modulesQuickJSVersion: string;
};

@route("/gov/kv/nodes/code_ids")
@get op getNodeCodeIds(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body nodeCodeIds: CodeDigestToCodeStatus;
};

@route("/gov/kv/nodes/endorsed_certificates")
@get op getNodesEndorsedCertificates(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body nodesEndorsedCertificates: NodeIdToPem;
};

@route("/gov/kv/nodes/info")
@get op getNodesInfo(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body nodesInfo: NodeIdToNodeInfo;
};

@route("/gov/kv/nodes/snp/host_data")
@get op getNodeSnpHostData(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body nodesSnpHostData: Sha256DigestToString;
};

@route("/gov/kv/nodes/snp/measurements")
@get op getNodeSnpMeasurements(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body nodesSnpMeasurements: CodeDigestToCodeStatus;
};

@route("/gov/kv/proposals")
@get op getProposals(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body proposals: StringToBase64;
};

@route("/gov/kv/proposals_info")
@get op getProposalsInfo(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body proposalsInfo: StringToProposalInfo;
};

@route("/gov/kv/service/acme_certificates")
@get op getServiceAcmeCertificates(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body serviceAcmeCertificates: StringToPem;
};

@route("/gov/kv/service/config")
@get op getServiceConfig(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body serviceConfig: ServiceConfiguration;
};

@route("/gov/kv/service/info")
@get op getServiceInfo(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body serviceInfo: ServiceInfo;
};

@route("/gov/kv/service/previous_service_identity")
@get op getServicePreviousServiceIdentity(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body servicePreviousServiceIdentity: Pem;
};

@route("/gov/kv/tls/ca_cert_bundles")
@get op getTlsCaCertBundles(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body tlsCaCertBundles: string;
};

@route("/gov/kv/users/certs")
@get op getUsersCerts(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body usersCerts: UserIdToPem;
};

@route("/gov/kv/users/info")
@get op getUsersInfo(): {
    @header("x-ms-ccf-transaction-id") transactionID: string;
    @body usersInfo: UserDetails;
};

@route("/gov/proposals")
namespace proposal {
    @summary("Proposed changes to the service pending resolution")
    @get op allProposals(): {
        @header("x-ms-ccf-transaction-id") transactionID: string;
    @body proposals: StringToProposalInfo
    };
    @summary("Submit a proposed change to the service")
    @post op proposalInfo(@body proposal: Proposal): {
        @header("x-ms-ccf-transaction-id") transactionID: string;
    @body proposalInfoDetail: ProposalInfoSummary;
    };
}

// A "global" RPC operation
@route("service-status")
@doc("Responds with status information about the overall service.")
op serviceStatus is RpcOperation<
  {},
  {
    statusString: string;
  },
  ServiceTraits
>;