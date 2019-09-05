// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "certs.h"
#include "clientsignatures.h"
#include "codeid.h"
#include "entities.h"
#include "members.h"
#include "nodes.h"
#include "proposals.h"
#include "scripts.h"
#include "secrets.h"
#include "service.h"
#include "signatures.h"
#include "values.h"
#include "votinghistory.h"
#include "whitelists.h"

#include <memory>
#include <tuple>

namespace ccf
{
  struct NetworkTables
  {
    std::shared_ptr<Store> tables;

    // Governance tables
    Members& members;
    Certs& member_certs;
    Scripts& gov_scripts;
    Proposals& proposals;
    Whitelists& whitelists;
    CodeIDs& code_id;
    MemberAcks& member_acks;
    VotingHistoryTable& voting_history;
    ClientSignatures& member_client_signatures;

    // User tables
    Certs& user_certs;
    ClientSignatures& user_client_signatures;

    // Node tables
    Nodes& nodes;
    Certs& node_certs;

    // Lua application table
    Scripts& app_scripts;

    // Internal CCF tables
    Service& service;
    Values& values;
    Secrets& secrets_table;
    Signatures& signatures;

    NetworkTables() :
      tables(std::make_shared<Store>()),
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
      code_id(
        tables->create<CodeIDs>(Tables::CODEID, kv::SecurityDomain::PUBLIC)),
      member_acks(tables->create<MemberAcks>(
        Tables::MEMBER_ACKS, kv::SecurityDomain::PUBLIC)),
      voting_history(tables->create<VotingHistoryTable>(
        Tables::VOTING_HISTORY, kv::SecurityDomain::PUBLIC)),
      member_client_signatures(
        tables->create<ClientSignatures>(Tables::MEMBER_CLIENT_SIGNATURES)),
      user_certs(tables->create<Certs>(Tables::USER_CERTS)),
      user_client_signatures(
        tables->create<ClientSignatures>(Tables::USER_CLIENT_SIGNATURES)),
      nodes(tables->create<Nodes>(Tables::NODES, kv::SecurityDomain::PUBLIC)),
      node_certs(
        tables->create<Certs>(Tables::NODE_CERTS, kv::SecurityDomain::PUBLIC)),
      app_scripts(tables->create<Scripts>(
        Tables::APP_SCRIPTS, kv::SecurityDomain::PUBLIC)),
      service(
        tables->create<Service>(Tables::SERVICE, kv::SecurityDomain::PUBLIC)),
      values(
        tables->create<Values>(Tables::VALUES, kv::SecurityDomain::PUBLIC)),
      secrets_table(
        tables->create<Secrets>(Tables::SECRETS, kv::SecurityDomain::PUBLIC)),
      signatures(tables->create<Signatures>(
        Tables::SIGNATURES, kv::SecurityDomain::PUBLIC))
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
        std::ref(code_id),
        std::ref(member_acks),
        std::ref(voting_history),
        std::ref(member_client_signatures),
        std::ref(user_certs),
        std::ref(user_client_signatures),
        std::ref(nodes),
        std::ref(node_certs),
        std::ref(service),
        std::ref(app_scripts),
        std::ref(values),
        std::ref(signatures));
    }
  };
}