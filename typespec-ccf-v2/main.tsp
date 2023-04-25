import "@typespec/http";
import "@typespec/versioning";

import "./transactions.tsp";
import "./proposals.tsp";

@service({
  title: "Managed CCF Governance",
})
@TypeSpec.Versioning.versioned(Microsoft.ManagedCcf.Versions)
namespace Microsoft.ManagedCcf;

enum Versions {
  @TypeSpec.Versioning.useDependency(Azure.Core.Versions.v1_0_Preview_2)
  `0.0.1-preview`,
}

@TypeSpec.Http.route("gov")
interface Gov extends Transactions, Proposals, Ballots, Acks {}
