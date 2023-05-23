import "@typespec/http";
import "@typespec/rest";
import "@typespec/versioning";
import "@azure-tools/typespec-azure-core";

import "./common.tsp";

@TypeSpec.Versioning.useDependency(Azure.Core.Versions.v1_0_Preview_2)
namespace ServiceState;

/// Common types
@doc("PEM encoding of a cryptographic identifier. Contains a base64-encoded payload wrapped in content type identifiers.")
scalar pem extends string;

/// Member types
@doc("Possible states for a CCF governing member.")
enum MemberStatus {
  @doc("Member has been approved to join the service, but have not yet submitted an ACK to indicate their participation. These members should not be considered by constitutions in quorum calculations, and their signed requests will be rejected until they become Active.")
  Accepted,

  @doc("Member has submitted a valid ACK and is a full voting participant.")
  Active,
}

@doc("Information on individual members within a consortium.")
@TypeSpec.Rest.resource("service/members")
model Member {
  @doc("ID of CCF member who this object refers to.")
  @visibility("read")
  @key
  memberId: memberId;

  @doc("Current status of this member.")
  status: MemberStatus;

  @doc("Arbitrary service-defined metadata about this member. May be used by constitution or application code, but will not affect any core framework decisions.")
  memberData: {};

  @doc("x509 certificate used as this member's identity.")
  certificate: pem;
}

/// Node types
@doc("TODO")
enum NodeStatus {
  @doc("TODO")
  Pending,

  @doc("TODO")
  Trusted,

  @doc("TODO")
  Retired,
}

@doc("TODO")
@discriminator("format")
model QuoteInfo {}

@doc("TODO")
model SgxQuoteInfo {
  @doc("TODO")
  format: "OE_SGX_v1";

  @doc("TODO")
  quote: string; // base64

  @doc("TODO")
  endorsements: string; // base64
}

@doc("TODO")
model SnpQuoteInfo {
  @doc("TODO")
  format: "AMD_SEV_SNP_v1";

  @doc("TODO")
  uvmEndorsements: string; // base64

  @doc("TODO")
  endorsedTcb: string; // base64
}

@doc("TODO")
model NetworkInterface {
  @doc("TODO")
  publishedAddress: string;

  @doc("TODO")
  protocol: string;
}

@doc("Information on individual nodes within a service.")
@TypeSpec.Rest.resource("service/nodes")
model Node {
  @doc("ID of CCF node who this object refers to.")
  @visibility("read")
  @key
  nodeId: nodeId;

  @doc("Current status of this node.")
  status: NodeStatus;

  @doc("Arbitrary service-defined metadata about this node. May be used by constitution or application code, but will not affect any core framework decisions.")
  nodeData: {};

  @doc("x509 certificate containing this node's identity.")
  certificate: pem;

  @doc("TODO")
  retiredCommitted: boolean;

  @doc("TODO")
  quoteInfo: QuoteInfo;

  @doc("TODO")
  nodeToNodeInterface: NetworkInterface;

  @doc("TODO")
  rpcInterfaces: Record<NetworkInterface>;
}

/// constitution types
@TypeSpec.Rest.resource("service")
@doc("Constitution used to make governance decisions on the service. All governance changes are presented as proposals which must be validated, approved, and applied by the code in this constitution.")
model ConstitutionResponse {
  @doc("Singleton key for accessing constitution")
  @visibility("read")
  @key
  id: "constitution";

  @doc("Javascript source code of constitution.")
  constitution: string;
}

/// JS app types
@doc("TODO")
enum ForwardingRequired {
  @doc("TODO")
  Sometimes,

  @doc("TODO")
  Always,

  @doc("TODO")
  Never,
}

@doc("TODO")
enum JsExecMode {
  @doc("TODO")
  ReadWrite,

  @doc("TODO")
  ReadOnly,

  @doc("TODO")
  Historical,
}

@doc("TODO")
model JsEndpointInfo {
  @doc("TODO")
  jsModule: string;

  @doc("TODO")
  jsFunction: string;

  @doc("TODO")
  forwardingRequired: ForwardingRequired;

  @doc("TODO")
  authnPolicies: string[];

  @doc("TODO")
  mode: JsExecMode;

  @doc("TODO")
  memberData: {};
}

alias JsEndpoint = Record<JsEndpointInfo>;

@TypeSpec.Rest.resource("service")
@doc("TODO")
model JsApp {
  @doc("Singleton key for accessing javaScriptApp")
  @visibility("read")
  @key
  // TODO: javascript-app?
  id: "javaScriptApp";

  @doc("TODO")
  endpoints: Record<JsEndpoint>;

  // TODO:
  // - Endpoint source?
  // - Module source?
  // - Engine config?
  // - QuickJS version
}

/// Join policy types
@doc("TODO")
model JoinPolicy {
  @doc("TODO")
  measurements: string[];
}

@doc("TODO")
model SnpJoinPolicy {
  ...JoinPolicy;
  // TODO: Work out what the actual types of these are


  @doc("TODO")
  hostData: Record<string>;

  @doc("TODO")
  uvmEndorsements: Record<string>;
}

@TypeSpec.Rest.resource("service")
@doc("TODO")
model JoinPolicies {
  @doc("TODO")
  @visibility("read")
  @key
  // TODO: join-policy?
  id: "joinPolicy";

  @doc("TODO")
  sgx: JoinPolicy;

  @doc("TODO")
  snp: SnpJoinPolicy;
}

/// JWK/JWT types
@doc("TODO")
model JwtIssuer {
  // TODO
}

@doc("Chain of endorsed certificates (PEM format) leading to a CA.")
scalar caCertBundle extends string;

@TypeSpec.Rest.resource("service")
@doc("TODO")
model JwkInfo {
  @doc("TODO")
  @visibility("read")
  @key
  // TODO: join-policy?
  id: "jwk";

  @doc("TODO")
  issuers: Record<JwtIssuer>;

  @doc("TODO")
  caCertBundles: Record<caCertBundle>;
}

/// Service info types
@doc("TODO")
enum ServiceStatus {
  @doc("TODO")
  Opening,

  @doc("TODO")
  Open,

  @doc("TODO")
  WaitingForRecoveryShares,

  @doc("TODO")
  Recovering,
}

@doc("TODO")
@TypeSpec.Rest.resource("service")
model ServiceInfo {
  @doc("TODO")
  @visibility("read")
  @key
  id: "info";

  @doc("TODO")
  status: ServiceStatus;

  @doc("The current service identity. This is the public face of a secret key shared only by the nodes within the service, and should be used to authenticate TLS sessions with this service.")
  certificate: pem;

  @doc("TODO")
  recoveryCount: safeint;

  @doc("Transaction ID at which this service was first created. If this is a recovery of a previous service, this will indicate when the current service was recovered.")
  creationTransactionId: transactionId;

  @doc("Transaction ID at which the predecessor service was created, if this service is a recovery. If this is an original service rather than a recovery, this will be omitted.")
  previousServiceCreationTransactionId?: pem;

  @doc("TODO")
  serviceData: {};

  @doc("TODO")
  configuration: {
    maximumNodeCertificateValidityDays: safeint;
    recentCoseProposalsWindowSize: safeint;
  };
}

interface ServiceState {
  @doc("Retrieve list of all members who govern this service.")
  getAllMembers is Azure.Core.StandardResourceOperations.ResourceList<
    Member,
    TxIdReadHeader
  >;

  @doc("Retrieve info on a single governing member, by ID.")
  getMember is Azure.Core.StandardResourceOperations.ResourceRead<
    Member,
    TxIdReadHeader
  >;

  @doc("TODO")
  getAllNodes is Azure.Core.StandardResourceOperations.ResourceList<
    Node,
    TxIdReadHeader
  >;

  @doc("TODO")
  getNode is Azure.Core.StandardResourceOperations.ResourceRead<
    Node,
    TxIdReadHeader
  >;

  @doc("Retrieve the constitution which controls governance changes on this service.")
  getConstitution is Azure.Core.StandardResourceOperations.ResourceRead<
    ConstitutionResponse,
    TxIdReadHeader
  >;

  @doc("TODO")
  getJsApp is Azure.Core.StandardResourceOperations.ResourceRead<
    JsApp,
    TxIdReadHeader
  >;

  @doc("TODO")
  getJoinPolicies is Azure.Core.StandardResourceOperations.ResourceRead<
    JoinPolicies,
    TxIdReadHeader
  >;

  @doc("Returns information about OpenID Connect identity providers.")
  getJwkInfo is Azure.Core.StandardResourceOperations.ResourceRead<
    JwkInfo,
    TxIdReadHeader
  >;

  @doc("Returns information about service.")
  getServiceInfo is Azure.Core.StandardResourceOperations.ResourceRead<
    ServiceInfo,
    TxIdReadHeader
  >;
}
