import "@typespec/http";
import "@typespec/versioning";

import "./transactions.tsp";
import "./consortium.tsp";

@service({
  title: "Managed CCF Governance",
})
@TypeSpec.Versioning.versioned(Microsoft.ManagedCcf.Versions)
namespace Microsoft.ManagedCcf;

enum Versions {
  @TypeSpec.Versioning.useDependency(Azure.Core.Versions.v1_0_Preview_2)
  `0.0.1-preview`,
}

@TypeSpec.Http.route("/gov/members")
interface ConsortiumGov extends Proposals, Ballots, Acks, RecoveryShares {}

@TypeSpec.Http.route("/gov/service")
interface ServiceInfo extends Transactions {}
