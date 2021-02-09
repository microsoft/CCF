// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "backup_signatures.h"
#include "certs.h"
#include "client_signatures.h"
#include "code_id.h"
#include "config.h"
#include "consensus/aft/raft_tables.h"
#include "consensus/aft/request.h"
#include "consensus/aft/revealed_nonces.h"
#include "entities.h"
#include "governance_history.h"
#include "jwt.h"
#include "kv/map.h"
#include "kv/store.h"
#include "members.h"
#include "modules.h"
#include "nodes.h"
#include "proposals.h"
#include "scripts.h"
#include "secrets.h"
#include "service.h"
#include "service_principals.h"
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
    // members, member_certs and member_digests tables should always be in sync
    Members members;
    CertDERs member_certs;
    CertDigests member_digests;

    Scripts gov_scripts;
    Modules modules;
    Proposals proposals;
    Whitelists whitelists;
    CodeIDs node_code_ids;
    MemberAcks member_acks;
    GovernanceHistory governance_history;
    RecoveryShares shares;
    EncryptedLedgerSecretsInfo encrypted_ledger_secrets;
    SubmittedShares submitted_shares;
    Configuration config;

    CACertDERs ca_certs;

    JwtIssuers jwt_issuers;
    JwtPublicSigningKeys jwt_public_signing_keys;
    JwtPublicSigningKeyIssuer jwt_public_signing_key_issuer;

    //
    // User tables
    //
    // users, user_certs and user_digests tables should always be in sync
    Users users;
    CertDERs user_certs;
    CertDigests user_digests;

    ServicePrincipals service_principals;

    //
    // Node table
    //
    Nodes nodes;

    //
    // JS application table
    //
    Scripts app_scripts;

    //
    // Internal CCF tables
    //
    Service service;
    Values values;
    Secrets secrets;
    Signatures signatures;
    SnapshotEvidence snapshot_evidence;

    //
    // bft related tables
    //
    aft::RequestsMap bft_requests_map;
    BackupSignaturesMap backup_signatures_map;
    aft::RevealedNoncesMap revealed_nonces_map;
    NewViewsMap new_views_map;

    NetworkTables(const ConsensusType& consensus_type = ConsensusType::CFT) :
      tables(
        (consensus_type == ConsensusType::CFT) ?
          std::make_shared<kv::Store>(
            aft::replicate_type_raft, aft::replicated_tables_raft) :
          std::make_shared<kv::Store>(
            aft::replicate_type_bft, aft::replicated_tables_bft)),
      members(Tables::MEMBERS),
      member_certs(Tables::MEMBER_CERT_DERS),
      member_digests(Tables::MEMBER_DIGESTS),
      gov_scripts(Tables::GOV_SCRIPTS),
      modules(Tables::MODULES),
      proposals(Tables::PROPOSALS),
      whitelists(Tables::WHITELISTS),
      node_code_ids(Tables::NODE_CODE_IDS),
      member_acks(Tables::MEMBER_ACKS),
      governance_history(Tables::GOV_HISTORY),
      shares(Tables::SHARES),
      encrypted_ledger_secrets(Tables::ENCRYPTED_PAST_LEDGER_SECRET),
      submitted_shares(Tables::SUBMITTED_SHARES),
      config(Tables::CONFIGURATION),
      ca_certs(Tables::CA_CERT_DERS),
      jwt_issuers(Tables::JWT_ISSUERS),
      jwt_public_signing_keys(Tables::JWT_PUBLIC_SIGNING_KEYS),
      jwt_public_signing_key_issuer(Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER),
      users(Tables::USERS),
      user_certs(Tables::USER_CERT_DERS),
      user_digests(Tables::USER_DIGESTS),
      service_principals(Tables::SERVICE_PRINCIPALS),
      nodes(Tables::NODES),
      app_scripts(Tables::APP_SCRIPTS),
      service(Tables::SERVICE),
      values(Tables::VALUES),
      secrets(Tables::ENCRYPTED_LEDGER_SECRETS),
      signatures(Tables::SIGNATURES),
      snapshot_evidence(Tables::SNAPSHOT_EVIDENCE),
      bft_requests_map(Tables::AFT_REQUESTS),
      backup_signatures_map(Tables::BACKUP_SIGNATURES),
      revealed_nonces_map(Tables::NONCES),
      new_views_map(Tables::NEW_VIEWS)
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
        std::ref(config),
        std::ref(ca_certs),
        std::ref(jwt_issuers),
        std::ref(jwt_public_signing_keys),
        std::ref(jwt_public_signing_key_issuer),
        std::ref(users),
        std::ref(user_certs),
        std::ref(service_principals),
        std::ref(nodes),
        std::ref(service),
        std::ref(app_scripts),
        std::ref(values),
        std::ref(signatures));
    }
  };
}