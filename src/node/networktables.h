// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "calltypes.h"
#include "certs.h"
#include "clientsignatures.h"
#include "codeid.h"
#include "consensus/pbft/pbftpreprepares.h"
#include "consensus/pbft/pbftrequests.h"
#include "consensus/pbft/pbfttables.h"
#include "consensus/raft/rafttables.h"
#include "entities.h"
#include "governancehistory.h"
#include "members.h"
#include "nodes.h"
#include "proposals.h"
#include "scripts.h"
#include "secrets.h"
#include "service.h"
#include "shares.h"
#include "signatures.h"
#include "users.h"
#include "values.h"
#include "whitelists.h"

#include <memory>
#include <tuple>

namespace ccf
{
  struct NetworkTables
  {
    std::shared_ptr<Store> tables;

    //
    // Governance tables
    //
    // members and member_certs tables should always be in sync
    Members& members;
    Certs& member_certs;

    Scripts& gov_scripts;
    Proposals& proposals;
    Whitelists& whitelists;
    CodeIDs& code_ids;
    MemberAcks& member_acks;
    GovernanceHistory& governance_history;
    ClientSignatures& member_client_signatures;
    Shares& shares;

    //
    // User tables
    //
    // users and user_certs tables should always be in sync
    Users& users;
    Certs& user_certs;

    ClientSignatures& user_client_signatures;

    //
    // Node table
    //
    Nodes& nodes;

    //
    // Lua application table
    //
    Scripts& app_scripts;

    //
    // Internal CCF tables
    //
    Service& service;
    Values& values;
    Secrets& secrets;
    Signatures& signatures;

    //
    // Pbft related tables
    //
    pbft::RequestsMap& pbft_requests_map;
    pbft::PrePreparesMap& pbft_pre_prepares_map;

    NetworkTables(const ConsensusType& consensus_type = ConsensusType::Raft) :
      tables(
        (consensus_type == ConsensusType::Raft) ?
          std::make_shared<Store>(
            raft::replicate_type_raft, raft::replicated_tables_raft) :
          std::make_shared<Store>(
            pbft::replicate_type_pbft, pbft::replicated_tables_pbft)),
      members(
        tables->create<Members>(Tables::MEMBERS, kv::SecurityDomain::PUBLIC)),
      member_certs(tables->create<Certs>(
        Tables::MEMBER_CERTS, kv::SecurityDomain::PUBLIC)),
      gov_scripts(tables->create<Scripts>(
        Tables::GOV_SCRIPTS, kv::SecurityDomain::PUBLIC)),
      proposals(tables->create<Proposals>(
        Tables::PROPOSALS, kv::SecurityDomain::PUBLIC)),
      whitelists(tables->create<Whitelists>(
        Tables::WHITELISTS, kv::SecurityDomain::PUBLIC)),
      code_ids(
        tables->create<CodeIDs>(Tables::CODE_IDS, kv::SecurityDomain::PUBLIC)),
      member_acks(tables->create<MemberAcks>(
        Tables::MEMBER_ACKS, kv::SecurityDomain::PUBLIC)),
      governance_history(tables->create<GovernanceHistory>(
        Tables::GOV_HISTORY, kv::SecurityDomain::PUBLIC)),
      member_client_signatures(
        tables->create<ClientSignatures>(Tables::MEMBER_CLIENT_SIGNATURES)),
      shares(
        tables->create<Shares>(Tables::SHARES, kv::SecurityDomain::PUBLIC)),
      users(tables->create<Users>(Tables::USERS)),
      user_certs(tables->create<Certs>(Tables::USER_CERTS)),
      user_client_signatures(
        tables->create<ClientSignatures>(Tables::USER_CLIENT_SIGNATURES)),
      nodes(tables->create<Nodes>(Tables::NODES, kv::SecurityDomain::PUBLIC)),
      app_scripts(tables->create<Scripts>(
        Tables::APP_SCRIPTS, kv::SecurityDomain::PUBLIC)),
      service(
        tables->create<Service>(Tables::SERVICE, kv::SecurityDomain::PUBLIC)),
      values(
        tables->create<Values>(Tables::VALUES, kv::SecurityDomain::PUBLIC)),
      secrets(
        tables->create<Secrets>(Tables::SECRETS, kv::SecurityDomain::PUBLIC)),
      signatures(tables->create<Signatures>(
        Tables::SIGNATURES, kv::SecurityDomain::PUBLIC)),
      pbft_requests_map(
        tables->create<pbft::RequestsMap>(pbft::Tables::PBFT_REQUESTS)),
      pbft_pre_prepares_map(
        tables->create<pbft::PrePreparesMap>(pbft::Tables::PBFT_PRE_PREPARES))
    {}

    /** Returns a tuple of all tables that are possibly accessible from scripts
     * (app and gov). More fine-grained access control is applied via
     * whitelists.
     */
    auto get_scriptable_tables() const
    {
      return std::make_tuple(
        std::ref(members),
        std::ref(member_certs),
        std::ref(gov_scripts),
        std::ref(proposals),
        std::ref(whitelists),
        std::ref(code_ids),
        std::ref(member_acks),
        std::ref(governance_history),
        std::ref(member_client_signatures),
        std::ref(users),
        std::ref(user_certs),
        std::ref(user_client_signatures),
        std::ref(nodes),
        std::ref(service),
        std::ref(app_scripts),
        std::ref(values),
        std::ref(signatures));
    }
  };
}