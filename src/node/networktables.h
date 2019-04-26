// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "attestationca.h"
#include "certs.h"
#include "clientsignatures.h"
#include "codeid.h"
#include "entities.h"
#include "members.h"
#include "nodes.h"
#include "proposals.h"
#include "scripts.h"
#include "secrets.h"
#include "signatures.h"
#include "values.h"
#include "whitelists.h"

#include <memory>
#include <tuple>

namespace ccf
{
  struct NetworkTables
  {
    std::shared_ptr<Store> tables;
    Members& members;
    MemberAcks& member_acks;
    Certs& member_certs;
    Certs& user_certs;
    Certs& node_certs;
    Values& values;
    Nodes& nodes;
    Signatures& signatures;
    AttestationCAs& attestation_cas;
    ClientSignatures& user_client_signatures;
    ClientSignatures& member_client_signatures;
    Whitelists& whitelists;
    Proposals& proposals;
    Scripts& gov_scripts;
    Scripts& app_scripts;
    Secrets& secrets_table;
    CodeIDs& code_id;

    // TODO(#important): SERVICE table should be added.
    NetworkTables() :
      tables(std::make_shared<Store>()),
      members(
        tables->create<Members>(Tables::MEMBERS, kv::SecurityDomain::PUBLIC)),
      member_acks(tables->create<MemberAcks>(
        Tables::MEMBER_ACKS, kv::SecurityDomain::PUBLIC)),
      member_certs(tables->create<Certs>(
        Tables::MEMBER_CERTS, kv::SecurityDomain::PUBLIC)),
      user_certs(tables->create<Certs>(Tables::USER_CERTS)),
      node_certs(
        tables->create<Certs>(Tables::NODE_CERTS, kv::SecurityDomain::PUBLIC)),
      values(
        tables->create<Values>(Tables::VALUES, kv::SecurityDomain::PUBLIC)),
      nodes(tables->create<Nodes>(Tables::NODES, kv::SecurityDomain::PUBLIC)),
      signatures(tables->create<Signatures>(
        Tables::SIGNATURES, kv::SecurityDomain::PUBLIC)),
      attestation_cas(tables->create<AttestationCAs>(Tables::ATTESTATION_CAS)),
      user_client_signatures(
        tables->create<ClientSignatures>(Tables::USER_CLIENT_SIGNATURES)),
      member_client_signatures(
        tables->create<ClientSignatures>(Tables::MEMBER_CLIENT_SIGNATURES)),
      whitelists(tables->create<Whitelists>(
        Tables::WHITELISTS, kv::SecurityDomain::PUBLIC)),
      proposals(tables->create<Proposals>(
        Tables::PROPOSALS, kv::SecurityDomain::PUBLIC)),
      gov_scripts(tables->create<Scripts>(
        Tables::GOV_SCRIPTS, kv::SecurityDomain::PUBLIC)),
      app_scripts(tables->create<Scripts>(
        Tables::APP_SCRIPTS, kv::SecurityDomain::PUBLIC)),
      secrets_table(
        tables->create<Secrets>(Tables::SECRETS, kv::SecurityDomain::PUBLIC)),
      code_id(
        tables->create<CodeIDs>(Tables::CODEID, kv::SecurityDomain::PUBLIC))
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
        std::ref(member_acks),
        std::ref(user_certs),
        std::ref(node_certs),
        std::ref(values),
        std::ref(nodes),
        std::ref(signatures),
        std::ref(attestation_cas),
        std::ref(user_client_signatures),
        std::ref(member_client_signatures),
        std::ref(whitelists),
        std::ref(proposals),
        std::ref(gov_scripts),
        std::ref(app_scripts),
        std::ref(code_id));
    }
  };
}