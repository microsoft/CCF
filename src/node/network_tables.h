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
#include "kv/store.h"
#include "members.h"
#include "modules.h"
#include "nodes.h"
#include "proposals.h"
#include "scripts.h"
#include "secrets.h"
#include "service.h"
#include "service_map.h"
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
  inline std::shared_ptr<kv::Store> make_store(
    const ConsensusType& consensus_type)
  {
    if (consensus_type == ConsensusType::CFT)
    {
      return std::make_shared<kv::Store>(
        aft::replicate_type_raft, aft::replicated_tables_raft);
    }
    else
    {
      return std::make_shared<kv::Store>(
        aft::replicate_type_bft, aft::replicated_tables_bft);
    }
  }

  struct NetworkTables
  {
    std::shared_ptr<kv::Store> tables;

    //
    // Governance tables
    //
    MemberCerts member_certs;
    MmeberPublicEncryptionKeys member_encryption_public_keys;
    MemberInfo member_info;

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

    CACertBundlePEMs ca_cert_bundles;

    JwtIssuers jwt_issuers;
    JwtPublicSigningKeys jwt_public_signing_keys;
    JwtPublicSigningKeyIssuer jwt_public_signing_key_issuer;

    //
    // User tables
    //
    UserCerts user_certs;
    UserData user_data;

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
    SnapshotEvidence snapshot_evidence;

    // The signatures and serialised_tree tables should always be in sync
    Signatures signatures;
    SerialisedMerkleTree serialise_tree;

    //
    // bft related tables
    //
    aft::RequestsMap bft_requests_map;
    BackupSignaturesMap backup_signatures_map;
    aft::RevealedNoncesMap revealed_nonces_map;
    NewViewsMap new_views_map;

    NetworkTables(const ConsensusType& consensus_type = ConsensusType::CFT) :
      tables(make_store(consensus_type)),
      member_certs(Tables::MEMBER_CERTS),
      member_encryption_public_keys(Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS),
      member_info(Tables::MEMBER_INFO),
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
      ca_cert_bundles(Tables::CA_CERT_BUNDLE_PEMS),
      jwt_issuers(Tables::JWT_ISSUERS),
      jwt_public_signing_keys(Tables::JWT_PUBLIC_SIGNING_KEYS),
      jwt_public_signing_key_issuer(Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER),
      user_certs(Tables::USER_CERTS),
      user_data(Tables::USER_DATA),
      service_principals(Tables::SERVICE_PRINCIPALS),
      nodes(Tables::NODES),
      app_scripts(Tables::APP_SCRIPTS),
      service(Tables::SERVICE),
      values(Tables::VALUES),
      secrets(Tables::ENCRYPTED_LEDGER_SECRETS),
      snapshot_evidence(Tables::SNAPSHOT_EVIDENCE),
      signatures(Tables::SIGNATURES),
      serialise_tree(Tables::SERIALISED_MERKLE_TREE),
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
        std::ref(member_certs),
        std::ref(member_encryption_public_keys),
        std::ref(member_info),
        std::ref(gov_scripts),
        std::ref(modules),
        std::ref(proposals),
        std::ref(whitelists),
        std::ref(node_code_ids),
        std::ref(member_acks),
        std::ref(governance_history),
        std::ref(config),
        std::ref(ca_cert_bundles),
        std::ref(jwt_issuers),
        std::ref(jwt_public_signing_keys),
        std::ref(jwt_public_signing_key_issuer),
        std::ref(user_certs),
        std::ref(user_data),
        std::ref(service_principals),
        std::ref(nodes),
        std::ref(service),
        std::ref(app_scripts),
        std::ref(values),
        std::ref(signatures));
    }
  };
}