import "@typespec/http";
import "@typespec/rest";
import "@typespec/versioning";
import "@azure-tools/typespec-azure-core";

import "./common.tsp";

@TypeSpec.Versioning.useDependency(Azure.Core.Versions.v1_0_Preview_2)
namespace ServiceInfo;

@doc("PEM encoding of a cryptographic identifier. Contains a base64-encoded payload wrapped in content type identifiers.")
scalar pem extends string;

@doc("Possible states for a CCF governing member.")
enum MemberStatus {
  @doc("Member has been approved to join the service, but have not yet ACKed to indicate their participation. These members should not be considered by constitutions in quorum calculations, and their signed requests will be rejected until they become Active.")
  Accepted,

  @doc("Member has ACKed service state and is a full voting participant.")
  Active,
}

@doc("Information on individual members within a consortium.")
@TypeSpec.Rest.resource("service/consortium")
model MemberInfo {
  @doc("ID of CCF member who this data refers to.")
  @visibility("read")
  @key
  memberId: memberId;

  @doc("Current status of this member.")
  status: MemberStatus;
}

@TypeSpec.Rest.resource("service")
@doc("Constitution used to make governance decisions on the service. All governance changes are presented as proposals which must be validated, approved, and applied by the code in this constitution.")
model ConstitutionResponse {
  @doc("Singleton key for accessing constitution")
  @visibility("read")
  @key
  id: "constitution";

  @doc("Javascript source code of constitution.")
  constitution: string;

  @doc("Arbitrary service-defined metadata about this member. May be used by constitution or application code, but will not affect any core framework decisions.")
  // TODO: What should the type be?
  memberData: unknown;

  @doc("x509 certificate used as this member's identity.")
  certificate: pem;
}

interface ServiceInfo {
  /*
  TODO:
    GET /gov/service/javascriptApp
    GET /gov/service/nodes
    GET /gov/service/joinPolicy
    GET /gov/service/jwk
    GET /gov/service/info
  */

  // @doc("TODO")
  // @TypeSpec.Rest.action("constitution")
  // @TypeSpec.Rest.actionSeparator("/")
  // @TypeSpec.Http.get
  // getConstitution is Azure.Core.StandardResourceOperations.ResourceCollectionAction<
  //   Service,
  //   {},
  //   ConstitutionResponse & TxIdReadHeader
  // >;

  @doc("Retrieve list of all members who govern this service.")
  getConsortium is Azure.Core.StandardResourceOperations.ResourceList<
    MemberInfo,
    TxIdReadHeader
  >;

  @doc("Retrieve info on a single governing member, by ID.")
  getMemberInfo is Azure.Core.StandardResourceOperations.ResourceRead<
    MemberInfo,
    TxIdReadHeader
  >;

  @doc("Retrieve the constitution which controls governance changes on this service.")
  getConstitution is Azure.Core.StandardResourceOperations.ResourceRead<
    ConstitutionResponse,
    TxIdReadHeader
  >;
}
