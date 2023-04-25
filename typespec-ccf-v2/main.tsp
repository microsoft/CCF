import "@typespec/http";

import "./versions.tsp";
import "./transactions.tsp";
import "./proposals.tsp";

namespace Microsoft.ManagedCcf;

@TypeSpec.Http.route("gov")
interface Gov extends Transactions, Proposals
{
}

