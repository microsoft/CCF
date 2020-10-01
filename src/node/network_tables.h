// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "backup_signatures.h"
#include "call_types.h"
#include "certs.h"
#include "client_signatures.h"
#include "code_id.h"
#include "config.h"
#include "consensus.h"
#include "consensus/aft/raft_tables.h"
#include "consensus/aft/request.h"
#include "consensus/aft/revealed_nonces.h"
#include "entities.h"
#include "governance_history.h"
#include "kv/map.h"
#include "kv/store.h"
#include "members.h"
#include "modules.h"
#include "nodes.h"
#include "proposals.h"
#include "scripts.h"
#include "secrets.h"
#include "service.h"
#include "shares.h"
#include "signatures.h"
#include "snapshot_evidence.h"
#include "submitted_shares.h"
#include "users.h"
#include "values.h"
#include "whitelists.h"

#include <memory>
#include <tuple>

namespace ccf
{
  struct NetworkTables
  {
    std::shared_ptr<kv::Store> tables;

    //
    // Governance tables
    //
    // members and member_certs tables should always be in sync
    Members& members;
    CertDERs& member_certs;

    Scripts& gov_scripts;
    Modules& modules;
    Proposals& proposals;
    Whitelists& whitelists;
    CodeIDs& node_code_ids;
    MemberAcks& member_acks;
    GovernanceHistory& governance_history;
    ClientSignatures& member_client_signatures;
    Shares& shares;
    SubmittedShares& submitted_shares;
    Configuration& config;

    CACertDERs& ca_certs;

    //
    // User tables
    //
    // users and user_certs tables should always be in sync
    Users& users;
    CertDERs& user_certs;

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
    ConsensusTable& consensus;
    SnapshotEvidence& snapshot_evidence;

    //
    // bft related tables
    //
    aft::RequestsMap& bft_requests_map;
    BackupSignaturesMap& backup_signatures_map;
    aft::RevealedNoncesMap& revealed_nonces_map;

    NetworkTables(const ConsensusType& consensus_type = ConsensusType::CFT) :
      tables(
        (consensus_type == ConsensusType::CFT) ?
          std::make_shared<kv::Store>(
            aft::replicate_type_raft, aft::replicated_tables_raft) :
          std::make_shared<kv::Store>(
            aft::replicate_type_bft, aft::replicated_tables_bft)),
      members(
        tables->create<Members>(Tables::MEMBERS, kv::SecurityDomain::PUBLIC)),
      member_certs(tables->create<CertDERs>(
        Tables::MEMBER_CERT_DERS, kv::SecurityDomain::PUBLIC)),
      gov_scripts(tables->create<Scripts>(
        Tables::GOV_SCRIPTS, kv::SecurityDomain::PUBLIC)),
      modules(
        tables->create<Modules>(Tables::MODULES, kv::SecurityDomain::PUBLIC)),
      proposals(tables->create<Proposals>(
        Tables::PROPOSALS, kv::SecurityDomain::PUBLIC)),
      whitelists(tables->create<Whitelists>(
        Tables::WHITELISTS, kv::SecurityDomain::PUBLIC)),
      node_code_ids(tables->create<CodeIDs>(
        Tables::NODE_CODE_IDS, kv::SecurityDomain::PUBLIC)),
      member_acks(tables->create<MemberAcks>(
        Tables::MEMBER_ACKS, kv::SecurityDomain::PUBLIC)),
      governance_history(tables->create<GovernanceHistory>(
        Tables::GOV_HISTORY, kv::SecurityDomain::PUBLIC)),
      member_client_signatures(
        tables->create<ClientSignatures>(Tables::MEMBER_CLIENT_SIGNATURES)),
      shares(
        tables->create<Shares>(Tables::SHARES, kv::SecurityDomain::PUBLIC)),
      submitted_shares(tables->create<SubmittedShares>(
        Tables::SUBMITTED_SHARES, kv::SecurityDomain::PUBLIC)),
      config(tables->create<Configuration>(
        Tables::CONFIGURATION, kv::SecurityDomain::PUBLIC)),
      ca_certs(tables->create<CACertDERs>(
        Tables::CA_CERT_DERS, kv::SecurityDomain::PUBLIC)),
      users(tables->create<Users>(Tables::USERS, kv::SecurityDomain::PUBLIC)),
      user_certs(tables->create<CertDERs>(
        Tables::USER_CERT_DERS, kv::SecurityDomain::PUBLIC)),
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
      consensus(tables->create<ConsensusTable>(
        Tables::CONSENSUS, kv::SecurityDomain::PUBLIC)),
      snapshot_evidence(tables->create<SnapshotEvidence>(
        Tables::SNAPSHOT_EVIDENCE, kv::SecurityDomain::PUBLIC)),
      bft_requests_map(tables->create<aft::RequestsMap>(Tables::AFT_REQUESTS)),
      backup_signatures_map(tables->create<BackupSignaturesMap>(
        Tables::BACKUP_SIGNATURES, kv::SecurityDomain::PUBLIC)),
      revealed_nonces_map(tables->create<aft::RevealedNoncesMap>(
        Tables::NONCES, kv::SecurityDomain::PUBLIC))
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
        std::ref(modules),
        std::ref(proposals),
        std::ref(whitelists),
        std::ref(node_code_ids),
        std::ref(member_acks),
        std::ref(governance_history),
        std::ref(member_client_signatures),
        std::ref(config),
        std::ref(ca_certs),
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