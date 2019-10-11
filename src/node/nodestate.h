// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "calltypes.h"
#include "consensus/ledgerenclave.h"
#include "consensus/raft/raftconsensus.h"
#include "ds/logger.h"
#include "enclave/rpcclient.h"
#include "enclave/rpcsessions.h"
#include "encryptor.h"
#include "entities.h"
#include "genesisgen.h"
#include "history.h"
#include "networkstate.h"
#include "node/nodetonode.h"
#include "nodetonode.h"
#include "notifier.h"
#include "rpc/consts.h"
#include "rpc/frontend.h"
#include "rpc/serialization.h"
#include "seal.h"
#include "timer.h"
#include "tls/client.h"
#include "tls/entropy.h"

#ifdef PBFT
#  include "consensus/pbft/pbft.h"
#endif

#include <atomic>
#include <ccf_t.h>
#include <chrono>
#include <fmt/format_header_only.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <unordered_set>
#include <vector>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

namespace ccf
{
  using RaftConsensusType =
    raft::RaftConsensus<consensus::LedgerEnclave, NodeToNode>;
  using RaftType = raft::Raft<consensus::LedgerEnclave, NodeToNode>;

#ifdef PBFT
  using PbftConsensusType = pbft::Pbft<consensus::LedgerEnclave, NodeToNode>;
#endif

  template <typename T>
  class StateMachine
  {
    std::atomic<T> s;

  public:
    StateMachine(T s) : s(s) {}
    void expect(T s) const
    {
      if (s != this->s.load())
        throw std::logic_error("Unexpected state");
    }

    bool check(T s) const
    {
      return s == this->s.load();
    }

    void advance(T s)
    {
      this->s.store(s);
    }
  };

  class NodeState : public ccf::AbstractNodeState
  {
  private:
    template <typename T>
    using Result = std::pair<T, bool>;

    template <typename T>
    static Result<T> Success(T&& v)
    {
      return {std::forward<T>(v), true};
    }

    template <typename T>
    static Result<T> Fail()
    {
      return {{}, false};
    }

    template <typename T>
    static Result<T> Fail(const char* s)
    {
      LOG_DEBUG_FMT(s);
      return {{}, false};
    }

    enum class State
    {
      uninitialized,
      initialized,
      pending,
      partOfPublicNetwork,
      partOfNetwork,
      readingPublicLedger,
      readingPrivateLedger
    };

    //
    // this node's core state
    //
    StateMachine<State> sm;
    SpinLock lock;

    NodeId self;
    tls::KeyPairPtr node_kp;
    std::vector<uint8_t> node_cert;
    CodeDigest node_code_id;

    //
    // kv store, replication, and I/O
    //
    ringbuffer::AbstractWriterFactory& writer_factory;
    std::unique_ptr<ringbuffer::AbstractWriter> to_host;
    raft::Config raft_config;

    NetworkState& network;

    std::shared_ptr<kv::Consensus> consensus;
    std::shared_ptr<enclave::RpcMap> rpc_map;
    std::shared_ptr<NodeToNode> n2n_channels;
    enclave::RPCSessions& rpcsessions;
    ccf::Notifier& notifier;
    Timers& timers;

    std::shared_ptr<kv::TxHistory> history;
    std::shared_ptr<kv::AbstractTxEncryptor> encryptor;

    //
    // join protocol
    //
    std::vector<uint8_t> raw_fresh_key;
    std::map<NodeId, std::vector<uint8_t>> joiners_fresh_keys;
    jsonrpc::SeqNo join_seq_no = 1;
    std::shared_ptr<Timer> join_timer;

    //
    // recovery
    //
    NodeInfoNetwork node_info_network;
    std::shared_ptr<Store> recovery_store;
    std::shared_ptr<kv::TxHistory> recovery_history;
    std::shared_ptr<kv::AbstractTxEncryptor> recovery_encryptor;
    kv::Version recovery_v;
    crypto::Sha256Hash recovery_root;
    std::vector<kv::Version> term_history;
    kv::Version last_recovered_commit_idx = 1;

    consensus::Index ledger_idx = 0;

  public:
    NodeState(
      ringbuffer::AbstractWriterFactory& writer_factory,
      NetworkState& network,
      enclave::RPCSessions& rpcsessions,
      ccf::Notifier& notifier,
      Timers& timers) :
      sm(State::uninitialized),
      self(INVALID_ID),
      node_kp(tls::make_key_pair()),
      writer_factory(writer_factory),
      to_host(writer_factory.create_writer_to_outside()),
      network(network),
      rpcsessions(rpcsessions),
      notifier(notifier),
      timers(timers)
    {
      ::EverCrypt_AutoConfig2_init();
    }

    //
    // funcs in state "uninitialized"
    //
    void initialize(
      const raft::Config& raft_config_,
      std::shared_ptr<NodeToNode> n2n_channels_,
      std::shared_ptr<enclave::RpcMap> rpc_map_)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::uninitialized);

      raft_config = raft_config_;
      n2n_channels = n2n_channels_;
      // Capture rpc_map to pass to pbft for frontend execution
      rpc_map = rpc_map_;
      sm.advance(State::initialized);
    }

    //
    // funcs in state "initialized"
    //
    auto create(const CreateNew::In& args)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::initialized);

      // Generate node key pair
      std::stringstream name;
      name << "CN=" << Actors::NODES;
      node_cert = node_kp->self_sign(name.str());

      // Generate quote over node certificate
      // TODO: https://github.com/microsoft/CCF/issues/59
      std::vector<uint8_t> quote{1};

#ifdef GET_QUOTE
      auto quote_opt = get_quote();
      if (!quote_opt.has_value())
        return Fail<CreateNew::Out>("Quote could not be retrieved");
      quote = quote_opt.value();
#endif

      switch (args.start_type)
      {
        case StartType::New:
        {
          GenesisGenerator g(network);
          g.init_values();

          for (auto& cert : args.config.genesis.member_certs)
            g.add_member(cert);

          // Add self as TRUSTED
          self = g.add_node({args.config.node_info_network,
                             node_cert,
                             quote,
                             NodeStatus::TRUSTED});

#ifdef GET_QUOTE
          // Trust own code id
          g.trust_code_id(node_code_id);
#endif

          // set access whitelists
          // TODO(#feature): this should be configurable
          for (const auto& wl : default_whitelists)
            g.set_whitelist(wl.first, wl.second);

          g.set_gov_scripts(lua::Interpreter().invoke<nlohmann::json>(
            args.config.genesis.gov_script));

          network.secrets = std::make_unique<NetworkSecrets>(
            "CN=The CA", std::make_unique<Seal>(writer_factory));

          g.create_service(network.secrets->get_current().cert);

#ifdef PBFT
          setup_pbft();
#else
          setup_raft();
#endif
          setup_history();
          setup_encryptor();

          // Become the primary and force replication.
          consensus->force_become_primary();

          if (g.finalize() != kv::CommitSuccess::OK)
            return Fail<CreateNew::Out>(
              "Genesis transaction could not be committed");

          // Accept node connections for other nodes to join
          accept_node_connections();

          // Accept members connections for members to configure and open the
          // network
          accept_member_connections();

          sm.advance(State::partOfNetwork);

          return Success<CreateNew::Out>(
            {node_cert, quote, network.secrets->get_current().cert});
        }
        case StartType::Join:
        {
          // Generate fresh key to encrypt/decrypt historical network secrets
          // sent
          // by the primary via the kv store
          raw_fresh_key = tls::create_entropy()->random(crypto::GCM_SIZE_KEY);

          sm.advance(State::pending);
          return Success<CreateNew::Out>({node_cert, quote});
        }
        case StartType::Recover:
        {
          node_info_network = args.config.node_info_network;

          // Create temporary network secrets but do not seal yet
          network.secrets = std::make_unique<NetworkSecrets>(
            "CN=The CA", std::make_unique<Seal>(writer_factory), false);
          setup_history();
          setup_encryptor();

          // Accept members connections for members to finish recovery once the
          // public ledger has been read
          accept_member_connections();

          sm.advance(State::readingPublicLedger);

          return Success<CreateNew::Out>(
            {node_cert, quote, network.secrets->get_current().cert});
        }
        default:
        {
          throw std::logic_error(
            "Node was started in unknown mode " +
            std::to_string(args.start_type));
        }
      }
    }

    //
    // funcs in state "pending"
    //
    void initiate_join(const Join::In& args)
    {
      auto tls_ca = std::make_shared<tls::CA>(args.config.joining.network_cert);
      auto join_client_cert = std::make_unique<tls::Cert>(
        Actors::NODES, tls_ca, node_cert, node_kp->private_key_pem(), nullb);

      // Create RPC client and connect to remote node
      auto join_client = rpcsessions.create_client(std::move(join_client_cert));

      join_client->connect(
        args.config.joining.target_host,
        args.config.joining.target_port,
        [this](const std::vector<uint8_t>& data) {
          std::lock_guard<SpinLock> guard(lock);
          if (!sm.check(State::pending))
            return false;

          auto j = jsonrpc::unpack(data, jsonrpc::Pack::Text);

          // Check that the response is valid.
          jsonrpc::Response<JoinNetworkNodeToNode::Out> resp;
          try
          {
            resp = jsonrpc::Response<JoinNetworkNodeToNode::Out>(j);
          }
          catch (const std::exception& e)
          {
            LOG_FAIL_FMT(
              "An error occurred while joining the network {}", j.dump());
            return false;
          }

          // Set network secrets, node id and become part of network.
          if (resp->node_status == NodeStatus::TRUSTED)
          {
            // If the current network secrets do not apply since the genesis,
            // the joining node can only join the public network
            bool public_only = (resp->network_info.version != 0);

            // In a private network, seal secrets immediately.
            network.secrets = std::make_unique<NetworkSecrets>(
              resp->network_info.version,
              resp->network_info.network_secrets,
              std::make_unique<Seal>(writer_factory),
              !public_only);

            self = resp->node_id;
#ifdef PBFT
            setup_pbft();
#else
            setup_raft(public_only);
#endif
            setup_history();
            setup_encryptor();

            accept_node_connections();
            accept_member_connections();
            if (public_only)
              sm.advance(State::partOfPublicNetwork);
            else
              sm.advance(State::partOfNetwork);

            join_timer.reset();

            LOG_INFO_FMT(
              "Node has now joined the network as node {}: {}",
              self,
              (public_only ? "public only" : "all domains"));
          }
          else if (resp->node_status == NodeStatus::PENDING)
          {
            LOG_INFO_FMT(
              "Node {} is waiting for votes of members to be trusted",
              resp->node_id);
          }

          return true;
        });

      // Send RPC request to remote node to join the network.
      jsonrpc::ProcedureCall<JoinNetworkNodeToNode::In> join_rpc;
      join_rpc.id = join_seq_no++;
      join_rpc.method = ccf::NodeProcs::JOIN;
      join_rpc.params.raw_fresh_key = raw_fresh_key;
      join_rpc.params.node_info_network = args.config.node_info_network;

      // TODO: For now, regenerate the quote from when the node started. This
      // is OK since the quote generation will change as part of
      // https://github.com/microsoft/CCF/issues/59
      std::vector<uint8_t> quote{1};

#ifdef GET_QUOTE
      auto quote_opt = get_quote();
      if (!quote_opt.has_value())
        LOG_FATAL_FMT("Quote could not be retrieved");
      quote = quote_opt.value();
#endif
      join_rpc.params.quote = quote;

      LOG_DEBUG_FMT(
        "Sending join request to {}:{}",
        args.config.joining.target_host,
        args.config.joining.target_port);

      join_client->send(jsonrpc::pack(join_rpc, jsonrpc::Pack::Text));
    }

    void join(const Join::In& args)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::pending);

      initiate_join(args);

      using namespace std::chrono_literals;
      join_timer = timers.new_timer(1s, [this, args]() {
        if (sm.check(State::pending))
        {
          initiate_join(args);
          return true;
        }
        return false;
      });
      join_timer->start();
    }

    //
    // funcs in state "readingPublicLedger"
    //
    void start_ledger_recovery()
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::readingPublicLedger);
      LOG_INFO_FMT("Start public recovery");
      read_ledger_idx(++ledger_idx);
    }

    void recover_public_ledger_entry(const std::vector<uint8_t>& ledger_entry)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::readingPublicLedger);

      LOG_DEBUG_FMT(
        "Deserialising public ledger entry ({})", ledger_entry.size());

      // When reading the public ledger, deserialise in the real store
      auto result = network.tables->deserialise(ledger_entry, true);
      if (result == kv::DeserialiseSuccess::FAILED)
      {
        LOG_FAIL_FMT("Failed to deserialise entry in public ledger");
        network.tables->rollback(ledger_idx - 1);
        recover_public_ledger_end_unsafe();
        return;
      }

      // If the ledger entry is a signature, it is safe to compact the store
      if (result == kv::DeserialiseSuccess::PASS_SIGNATURE)
      {
        network.tables->compact(ledger_idx);
        GenesisGenerator g(network);
        auto last_sig = g.get_last_signature();
        if (last_sig.has_value())
        {
          LOG_DEBUG_FMT(
            "Read signature at {} for term {}", ledger_idx, last_sig->term);
          for (auto i = term_history.size(); i <= last_sig->term; ++i)
          {
            term_history.push_back(last_recovered_commit_idx + 1);
          }
          last_recovered_commit_idx = ledger_idx;
        }
        else
        {
          throw std::logic_error("Invalid signature");
        }
      }

      read_ledger_idx(++ledger_idx);
    }

    void recover_public_ledger_end_unsafe()
    {
      sm.expect(State::readingPublicLedger);

      // When reaching the end of the public ledger, truncate to last signed
      // index and promote network secrets to this index
      GenesisGenerator g(network);

      auto last_sig = g.get_last_signature();
      kv::Version last_index = 0;
      if (last_sig.has_value())
        last_index = last_sig->index;

      network.tables->rollback(last_index);
      ledger_truncate(last_index);
      LOG_INFO_FMT("Truncating ledger to last signed index: {}", last_index);

      network.secrets->promote_secrets(0, last_index + 1);

      g.create_service(network.secrets->get_current().cert, last_index + 1);

      g.retire_active_nodes();

      // Quotes should be initialised and non-empty
      std::vector<uint8_t> quote{1};

#ifdef GET_QUOTE
      auto quote_opt = get_quote();
      if (!quote_opt.has_value())
        LOG_FATAL_FMT("Quote could not be retrieved");
      quote = quote_opt.value();
#endif

      self =
        g.add_node({node_info_network, node_cert, quote, NodeStatus::PENDING});

      LOG_INFO_FMT("Deleted previous nodes and added self as {}", self);

      kv::Version index = 0;
      kv::Term term = 0;
      kv::Version global_commit = 0;

      auto ls = g.get_last_signature();
      if (ls.has_value())
      {
        auto s = ls.value();
        index = s.index;
        term = s.term;
        global_commit = s.commit;
      }

      auto h = dynamic_cast<MerkleTxHistory*>(history.get());
      if (h)
        h->set_node_id(self);

      setup_raft(true);

      LOG_DEBUG_FMT(
        "Restarting Raft at index: {} term: {} commit_idx {}",
        index,
        term,
        global_commit);
      consensus->force_become_primary(index, term, term_history, index);

      // Sets itself as trusted
      g.trust_node(self);

#ifdef GET_QUOTE
      g.trust_code_id(node_code_id);
#endif

      if (g.finalize() != kv::CommitSuccess::OK)
        throw std::logic_error(
          "Could not commit transaction when starting recovered public "
          "network");

      accept_node_connections();

      LOG_INFO_FMT("Restarted network");

      sm.advance(State::partOfPublicNetwork);
    }

    //
    // funcs in state "readingPrivateLedger"
    //
    void recover_private_ledger_entry(const std::vector<uint8_t>& ledger_entry)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::readingPrivateLedger);

      LOG_INFO_FMT(
        "Deserialising private ledger entry ({})", ledger_entry.size());

      // When reading the private ledger, deserialise in the recovery store
      auto result = recovery_store->deserialise(ledger_entry);
      if (result == kv::DeserialiseSuccess::FAILED)
      {
        LOG_FAIL_FMT("Failed to deserialise entry in private ledger");
        recovery_store->rollback(ledger_idx - 1);
        recover_private_ledger_end_unsafe();
        return;
      }

      if (result == kv::DeserialiseSuccess::PASS_SIGNATURE)
        recovery_store->compact(ledger_idx);

      if (recovery_store->current_version() == recovery_v)
      {
        LOG_INFO_FMT("Reached recovery final version at {}", recovery_v);
        recover_private_ledger_end_unsafe();
      }
      else
      {
        read_ledger_idx(++ledger_idx);
      }
    }

    void recover_private_ledger_end_unsafe()
    {
      sm.expect(State::readingPrivateLedger);

      // When reaching the end of the private ledger, make sure the same
      // ledger has been read and swap in private state
      auto h = dynamic_cast<MerkleTxHistory*>(recovery_history.get());
      if (h->get_root() != recovery_root)
      {
        LOG_FATAL_FMT(
          "Root of public store does not match root of private store");
      }

      network.tables->swap_private_maps(*recovery_store.get());
      recovery_store.reset();

      // Raft should deserialise all security domains when network is opened
      consensus->enable_all_domains();

      // On backups, resume replication
      if (!consensus->is_primary())
        consensus->resume_replication();

      // Seal all known network secrets
      network.secrets->seal_all();

      // Open the service
      if (consensus->is_primary())
      {
        GenesisGenerator g(network);
        if (!g.open_service())
          throw std::logic_error("Service could not be opened");

        if (g.finalize() != kv::CommitSuccess::OK)
          throw std::logic_error(
            "Could not commit transaction when finishing network recovery");
      }

      if (consensus->is_backup())
        accept_node_connections();

      sm.advance(State::partOfNetwork);
    }

    //
    // funcs in state "readingPublicLedger" or "readingPrivateLedger"
    //
    void recover_ledger_end()
    {
      std::lock_guard<SpinLock> guard(lock);

      if (is_reading_public_ledger())
      {
        recover_public_ledger_end_unsafe();
      }
      else if (is_reading_private_ledger())
      {
        recover_private_ledger_end_unsafe();
      }
      else
      {
        throw std::logic_error(
          "Cannot end ledger recovery if not reading public or private "
          "ledger");
      }
    }

    //
    // funcs in state "partOfPublicNetwork"
    //
    void setup_private_recovery_store()
    {
      // Setup recovery store by cloning tables of store
      recovery_store = std::make_shared<Store>();
      recovery_store->clone_schema(*network.tables);
      Signatures* recovery_signature_map =
        recovery_store->get<Signatures>(Tables::SIGNATURES);
      Nodes* recovery_nodes_map = recovery_store->get<Nodes>(Tables::NODES);

      recovery_history = std::make_shared<MerkleTxHistory>(
        *recovery_store.get(),
        self,
        *node_kp,
        *recovery_signature_map,
        *recovery_nodes_map);

      recovery_encryptor =
#ifdef USE_NULL_ENCRYPTOR
        std::make_shared<NullTxEncryptor>();
#else
        std::make_shared<TxEncryptor>(self, *network.secrets);
#endif

      recovery_store->set_history(recovery_history);
      recovery_store->set_encryptor(recovery_encryptor);

      // Record real store version and root
      recovery_v = network.tables->current_version();
      auto h = dynamic_cast<MerkleTxHistory*>(history.get());
      recovery_root = h->get_root();

      LOG_DEBUG_FMT("Recovery store successfully setup: {}", recovery_v);
    }

    bool finish_recovery(
      Store::Tx& tx, const nlohmann::json& sealed_secrets) override
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::partOfPublicNetwork);

      LOG_INFO_FMT("Initiating end of recovery (primary)");

      // Unseal past network secrets
      auto past_secrets_idx = network.secrets->restore(sealed_secrets);

      // Emit signature to certify transactions that happened on public
      // network
      history->emit_signature();

      // Write past network secrets to backups via secrets table
      auto [nodes_view, secrets_view] =
        tx.get_view(network.nodes, network.secrets_table);
      std::map<NodeId, NodeInfo> new_backups;
      nodes_view->foreach(
        [&new_backups, this](const NodeId& nid, const NodeInfo& ni) {
          if (ni.status != ccf::NodeStatus::RETIRED && nid != self)
            new_backups[nid] = ni;
          return true;
        });

      // For all nodes in the new network, write all past network secrets to
      // the secrets table, encrypted with the respective ephemeral keys
      for (auto const& ns_idx : past_secrets_idx)
      {
        ccf::PastNetworkSecrets past_secrets;
        for (auto [nid, ni] : new_backups)
        {
          ccf::SerialisedNetworkSecrets ns;
          ns.node_id = nid;

          auto serial = network.secrets->get_serialised_secret(ns_idx);
          if (serial.has_value())
          {
            LOG_DEBUG_FMT(
              "Writing network secret {} of size {} to backup {} in secrets "
              "table",
              ns_idx,
              serial.value().size(),
              nid);

            // Encrypt network secrets with joiner's fresh key
            auto search = joiners_fresh_keys.find(nid);
            if (search == joiners_fresh_keys.end())
            {
              LOG_FAIL_FMT("No fresh key for joiner {}", nid);
              continue;
            }

            crypto::KeyAesGcm joiner_key(
              CBuffer(search->second.data(), search->second.size()));
            crypto::GcmCipher gcmcipher(serial.value().size());

            // Get random IV
            auto iv = tls::create_entropy()->random(gcmcipher.hdr.getIv().n);
            std::copy(iv.begin(), iv.end(), gcmcipher.hdr.iv);

            joiner_key.encrypt(
              iv,
              CBuffer(serial.value().data(), serial.value().size()),
              CBuffer(),
              gcmcipher.cipher.data(),
              gcmcipher.hdr.tag);

            ns.serial_ns = gcmcipher.serialise();
            past_secrets.secrets.emplace_back(std::move(ns));
          }
          else
          {
            LOG_FAIL_FMT("Network secrets have not been restored: {}", ns_idx);
            return false;
          }
        }
        secrets_view->put(ns_idx, past_secrets);
      }

      // Setup new temporary store and record current version/root
      setup_private_recovery_store();

      // Start reading private security domain of ledger
      ledger_idx = 0;
      read_ledger_idx(++ledger_idx);

      sm.advance(State::readingPrivateLedger);
      return true;
    }

    //
    // funcs in state "partOfNetwork" or "partOfPublicNetwork"
    //
    void tick(std::chrono::milliseconds elapsed)
    {
      if (
        !sm.check(State::partOfNetwork) &&
        !sm.check(State::partOfPublicNetwork))
        return;

      consensus->periodic(elapsed);
    }

    void node_msg(const std::vector<uint8_t>& data)
    {
      // Only process messages once part of network
      if (
        !sm.check(State::partOfNetwork) &&
        !sm.check(State::partOfPublicNetwork))
      {
        return;
      }

      auto p = data.data();
      auto psize = data.size();
      Header header;
      NodeMsgType msg_type = serialized::overlay<NodeMsgType>(p, psize);

      switch (msg_type)
      {
        case channel_msg:
          n2n_channels->recv_message(p, psize);
          break;
        case consensus_msg:
          consensus->recv_message(p, psize);
          break;

        default:
        {}
      }
    }

    //
    // always available
    //
    bool is_primary() const override
    {
      return (
        (sm.check(State::partOfNetwork) ||
         sm.check(State::partOfPublicNetwork)) &&
        consensus->is_primary());
    }

    bool is_part_of_network() const override
    {
      return sm.check(State::partOfNetwork);
    }

    bool is_reading_public_ledger() const override
    {
      return sm.check(State::readingPublicLedger);
    }

    bool is_reading_private_ledger() const override
    {
      return sm.check(State::readingPrivateLedger);
    }

    bool is_part_of_public_network() const override
    {
      return sm.check(State::partOfPublicNetwork);
    }

    std::optional<std::vector<uint8_t>> get_quote()
    {
      std::vector<uint8_t> quote{1};

#ifdef GET_QUOTE
      // Quote is over the DER-encoded node certificate
      crypto::Sha256Hash h{node_cert};
      uint8_t* report;
      size_t report_len = 0;

      // TODO(#important,#TR): The "alpha" parameters, including the unique
      // service identifier, should also be included in the quote.
      oe_result_t res = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        h.h,
        h.SIZE,
        nullptr,
        0,
        &report,
        &report_len);

      if (res != OE_OK)
      {
        LOG_FAIL_FMT("Failed to get quote: {}", oe_result_str(res));
        return {};
      }

      quote.assign(report, report + report_len);
      oe_free_report(report);

      // Set own code version
      oe_report_t parsed_quote = {0};
      res = oe_parse_report(quote.data(), quote.size(), &parsed_quote);
      if (res != OE_OK)
      {
        LOG_FAIL_FMT("Failed to parse quote: {}", oe_result_str(res));
        return {};
      }

      std::copy(
        std::begin(parsed_quote.identity.unique_id),
        std::end(parsed_quote.identity.unique_id),
        std::begin(node_code_id));
#else
      throw std::logic_error("Quote retrieval is not yet implemented");
#endif
      return quote;
    }

    bool open_network(Store::Tx& tx) override
    {
      auto service_view = tx.get_view(network.service);

      auto active_service = service_view->get(0);
      if (!active_service.has_value())
      {
        LOG_FAIL_FMT("Failed to get active service");
        return false;
      }

      if (active_service->status != ServiceStatus::OPENING)
      {
        LOG_FAIL_FMT("Could not open current service: status is not OPENING");
        return false;
      }

      active_service->status = ServiceStatus::OPEN;
      service_view->put(0, active_service.value());

      return true;
    }

    // Used from nodefrontend.h to set the joiner's fresh key to encrypt past
    // network secrets
    void set_joiner_key(
      NodeId joiner_id, const std::vector<uint8_t>& raw_key) override
    {
      LOG_DEBUG_FMT("Setting fresh key for joiner {}", joiner_id);
      joiners_fresh_keys.emplace(joiner_id, raw_key);
    }

    void node_quotes(Store::Tx& tx, GetQuotes::Out& result) override
    {
      auto nodes_view = tx.get_view(network.nodes);

      nodes_view->foreach([&result](const NodeId& nid, const NodeInfo& ni) {
        if (ni.status == ccf::NodeStatus::TRUSTED)
        {
          LOG_FAIL_FMT("One node is trusted! {}", nid);
          GetQuotes::Quote quote;
          quote.node_id = nid;
          quote.raw = std::string(ni.quote.begin(), ni.quote.end());

#ifdef GET_QUOTE
          oe_report_t parsed_quote = {0};
          auto res =
            oe_parse_report(ni.quote.data(), ni.quote.size(), &parsed_quote);
          if (res != OE_OK)
          {
            quote.error =
              fmt::format("Failed to parse quote: {}", oe_result_str(res));
          }
          else
          {
            quote.mrenclave = fmt::format(
              "{:02x}", fmt::join(parsed_quote.identity.unique_id, ""));
          }
#endif
          result.quotes.push_back(quote);
        }
        return true;
      });
    };

  private:
    void accept_member_connections()
    {
      auto nw = tls::make_key_pair({network.secrets->get_current().priv_key});
      auto members_keypair = tls::make_key_pair();

      auto members_privkey = members_keypair->private_key_pem();
      auto members_cert =
        nw->sign_csr(members_keypair->create_csr("CN=members"), "CN=The CA");

      // Accept member connections.
      rpcsessions.add_cert(
        ccf::Actors::MEMBERS, nullb, members_cert, members_privkey);
    }

    void accept_node_connections()
    {
      auto nw = tls::make_key_pair({network.secrets->get_current().priv_key});
      auto nodes_keypair = tls::make_key_pair();

      auto nodes_privkey = nodes_keypair->private_key_pem();
      auto nodes_cert =
        nw->sign_csr(nodes_keypair->create_csr("CN=nodes"), "CN=The CA");

      // Accept node connections.
      rpcsessions.add_cert(
        ccf::Actors::NODES, nullb, nodes_cert, nodes_privkey);
    }

    void accept_user_connections()
    {
      auto nw = tls::make_key_pair({network.secrets->get_current().priv_key});
      auto users_keypair = tls::make_key_pair();

      auto users_privkey = users_keypair->private_key_pem();
      auto users_cert =
        nw->sign_csr(users_keypair->create_csr("CN=users"), "CN=The CA");

      // Accept user connections.
      rpcsessions.add_cert(
        ccf::Actors::USERS, nullb, users_cert, users_privkey);
    }

    void backup_finish_recovery()
    {
      if (!consensus->is_backup())
        return;

      sm.expect(State::partOfPublicNetwork);

      LOG_INFO_FMT("Initiating end of recovery (backup)");

      // Setup new temporary store and record current version/root
      setup_private_recovery_store();

      // Suspend consensus replication at recovery_v + 1 since this is called
      // from commit hook
      consensus->suspend_replication(recovery_v + 1);

      // Start reading private security domain of ledger
      ledger_idx = 0;
      read_ledger_idx(++ledger_idx);

      sm.advance(State::readingPrivateLedger);
    }

    void setup_basic_hooks()
    {
      // When a transaction that changes the configuration commits globally,
      // inform the host of any nodes that no longer need to be tracked.
      network.nodes.set_global_hook(
        [this](
          kv::Version version, const Nodes::State& s, const Nodes::Write& w) {
          for (auto& [node_id, ni] : w)
          {
            if (ni.value.status == NodeStatus::RETIRED)
              remove_node(node_id);
          }
        });

      network.service.set_global_hook([this](
                                        kv::Version version,
                                        const Service::State& s,
                                        const Service::Write& w) {
        if (w.at(0).value.status == ServiceStatus::OPEN)
        {
          this->consensus->set_f(
            1); // TODO: we should make f come from a KV table
          accept_user_connections();
          LOG_INFO_FMT("Now accepting user transactions");
        }
      });

      network.secrets_table.set_local_hook([this](
                                             kv::Version version,
                                             const Secrets::State& s,
                                             const Secrets::Write& w) {
        // If in backup mode in a public network, if new secrets are written
        // to the secrets table for our entry, decrypt these secrets and
        // initiate end of recovery protocol
        if (!(consensus->is_backup() && is_part_of_public_network()))
          return;

        bool has_secrets = false;

        for (auto& [v, past_secrets] : w)
        {
          for (auto& nw_secrets_at_v : past_secrets.value.secrets)
          {
            if (nw_secrets_at_v.node_id == self)
            {
              crypto::GcmCipher gcmcipher;
              gcmcipher.deserialise(nw_secrets_at_v.serial_ns);
              std::vector<uint8_t> plain_nw_secret_at_v(
                gcmcipher.cipher.size());

              crypto::KeyAesGcm fresh_key(raw_fresh_key);

              if (!fresh_key.decrypt(
                    gcmcipher.hdr.getIv(),
                    gcmcipher.hdr.tag,
                    gcmcipher.cipher,
                    CBuffer(),
                    plain_nw_secret_at_v.data()))
              {
                throw std::logic_error(
                  "Decryption of past network secrets failed");
              }

              has_secrets = true;
              if (!network.secrets->set_secret(v, plain_nw_secret_at_v))
              {
                throw std::logic_error(
                  "Cannot set secrets because they already exist!");
              }
            }
          }
        }
        if (has_secrets)
        {
          raw_fresh_key.clear();
          backup_finish_recovery();
        }
      });
    }

    void setup_n2n_channels()
    {
      // setup node-to-node channels
      n2n_channels->initialize(self, {network.secrets->get_current().priv_key});
    }

    void setup_raft(bool public_only = false)
    {
      setup_n2n_channels();

      auto raft = std::make_unique<RaftType>(
        std::make_unique<raft::Adaptor<Store, kv::DeserialiseSuccess>>(
          network.tables),
        std::make_unique<consensus::LedgerEnclave>(writer_factory),
        n2n_channels,
        self,
        std::chrono::milliseconds(raft_config.request_timeout),
        std::chrono::milliseconds(raft_config.election_timeout),
        public_only);

      consensus = std::make_shared<RaftConsensusType>(std::move(raft));

      network.tables->set_consensus(consensus);

      notifier.set_consensus(consensus);

      // When a node is added, even locally, inform the host so that it can
      // map the node id to a hostname and service and inform raft so that it
      // can add a new active configuration.
      network.nodes.set_local_hook(
        [this](
          kv::Version version, const Nodes::State& s, const Nodes::Write& w) {
          auto configure = false;
          std::unordered_set<NodeId> configuration;

          for (auto& [node_id, ni] : w)
          {
            switch (ni.value.status)
            {
              case NodeStatus::PENDING:
              {
                // Pending nodes are not added to consensus until they are
                // trusted
                break;
              }
              case NodeStatus::TRUSTED:
              {
                add_node(node_id, ni.value.host, ni.value.nodeport);
                configure = true;
                break;
              }
              case NodeStatus::RETIRED:
              {
                configure = true;
                break;
              }
              default:
              {}
            }
          }

          if (configure)
          {
            s.foreach([&](NodeId node_id, const Nodes::VersionV& v) {
              if (v.value.status == NodeStatus::TRUSTED)
                configuration.insert(node_id);
              return true;
            });
            consensus->add_configuration(version, move(configuration));
          }
        });

      setup_basic_hooks();
    }

    void setup_history()
    {
      // This function can be called once the node has started up and before
      // it has joined the service.
      history = std::make_shared<MerkleTxHistory>(
        *network.tables.get(),
        self,
        *node_kp,
        network.signatures,
        network.nodes);

      network.tables->set_history(history);
    }

    void setup_encryptor()
    {
      // This function makes use of network secrets and should be called once
      // the node has joined the service (either via start_network() or
      // join_network())
      encryptor =
#ifdef USE_NULL_ENCRYPTOR
        std::make_shared<NullTxEncryptor>();
#else
        std::make_shared<TxEncryptor>(self, *network.secrets);
#endif

      network.tables->set_encryptor(encryptor);
    }

    void add_node(
      NodeId node, const std::string& hostname, const std::string& service)
    {
      if (node != self)
      {
        RINGBUFFER_WRITE_MESSAGE(
          ccf::add_node, to_host, node, hostname, service);
      }
    }

    void remove_node(NodeId node)
    {
      if (node != self)
      {
        RINGBUFFER_WRITE_MESSAGE(ccf::remove_node, to_host, node);
      }
    }

    void read_ledger_idx(consensus::Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(consensus::ledger_get, to_host, idx);
    }

    void ledger_truncate(consensus::Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(consensus::ledger_truncate, to_host, idx);
    }

#ifdef PBFT
    void setup_pbft()
    {
      setup_n2n_channels();

      consensus = std::make_shared<PbftConsensusType>(
        std::make_unique<pbft::Adaptor<Store>>(network.tables),
        n2n_channels,
        self,
        std::make_unique<consensus::LedgerEnclave>(writer_factory),
        rpc_map,
        rpcsessions);

      network.tables->set_consensus(consensus);

      notifier.set_consensus(consensus);

      // When a node is added, even locally, inform the host so that it can
      // map the node id to a hostname and service and inform pbft
      network.nodes.set_local_hook(
        [this](
          kv::Version version, const Nodes::State& s, const Nodes::Write& w) {
          std::unordered_set<NodeId> configuration;
          for (auto& [node_id, ni] : w)
          {
            add_node(node_id, ni.value.host, ni.value.nodeport);
            consensus->add_configuration(
              version,
              configuration,
              {node_id, ni.value.host, ni.value.nodeport});
          }
        });

      setup_basic_hooks();
    }
#endif
  };
}
