import "@typespec/http";
import "@typespec/rest";
import "@azure-tools/typespec-azure-core";

@doc("TODO")
@TypeSpec.Rest.resource("proposals")
model Proposal {
  @key
  @doc("TODO")
  @pattern("TODO")
  @visibility("read")
  proposalId: string;

  @doc("TODO")
  @visibility("read")
  proposerId: string;

  // TODO: More fields
}

@doc("TODO")
@TypeSpec.Rest.resource("ballots")
@TypeSpec.Rest.parentResource(Proposal)
model Ballot
{
  @doc("TODO")
  @visibility("read")
  @key
  memberId: string;

  // TODO: More fields
}

interface Proposals
{
  @doc("TODO")
  getProposal is Azure.Core.ResourceRead<Proposal>;

  @doc("TODO")
  createProposal is Azure.Core.ResourceCreateWithServiceProvidedName<Proposal>;

  @doc("TODO")
  listOpenProposals is Azure.Core.ResourceList<Proposal, {}>;

  @doc("TODO")
  getBallot is Azure.Core.ResourceRead<Ballot>;
}

