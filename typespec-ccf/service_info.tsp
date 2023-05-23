import "@typespec/http";
import "@typespec/rest";
import "@typespec/versioning";
import "@azure-tools/typespec-azure-core";

import "./common.tsp";

@TypeSpec.Versioning.useDependency(Azure.Core.Versions.v1_0_Preview_2)
namespace ServiceInfo;

@TypeSpec.Rest.resource("service")
@doc("Describes the members who make up the service's governing consortium.")
model ConsortiumResponse {
  @doc("Singleton key for accessing consortium")
  @visibility("read")
  @key
  id: "consortium";

  @doc("Map from memberId to information about each member")
  // TODO: Should be map, memberId -> memberInfo
  consortium: string;
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

  @doc("Retrieve the members who govern this service.")
  getConsortium is Azure.Core.StandardResourceOperations.ResourceRead<
    ConsortiumResponse,
    TxIdReadHeader
  >;

  @doc("Retrieve the constitution which controls governance changes on this service.")
  getConstitution is Azure.Core.StandardResourceOperations.ResourceRead<
    ConstitutionResponse,
    TxIdReadHeader
  >;
}
