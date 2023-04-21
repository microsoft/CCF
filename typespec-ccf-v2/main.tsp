import "@typespec/rest";
import "@typespec/versioning";
import "@azure-tools/typespec-azure-core";

import "./transactions.tsp";
import "./proposals.tsp";

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
  `0.0.1-preview`,
}

@route("gov")
interface Gov extends Transactions, Proposals
{
}

