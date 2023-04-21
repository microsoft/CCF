import "@typespec/rest";
import "@typespec/versioning";
import "@azure-tools/typespec-azure-core";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;
using Azure.Core;
using Azure.Core.Traits;

@doc("TODO")
@resource("proposals")
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
@resource("ballots")
@parentResource(Proposal)
model Ballot
{
  @doc("TODO")
  @visibility("read")
  @key
  memberId: string;
}

interface Proposals
{
  @doc("TODO")
  getProposal is ResourceRead<Proposal>;

  @doc("TODO")
  createProposal is ResourceCreateWithServiceProvidedName<Proposal>;

  @doc("TODO")
  listOpenProposals is ResourceList<Proposal, {}>;

  @doc("TODO")
  getBallot is ResourceRead<Ballot>;
}

