// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "call_types.h"
#include "consensus/ledger_enclave.h"
#include "consensus/pbft/pbft.h"
#include "consensus/raft/raft_consensus.h"
#include "crypto/crypto_box.h"
#include "ds/logger.h"
#include "enclave/rpc_sessions.h"
#include "encryptor.h"
#include "entities.h"
#include "genesis_gen.h"
#include "history.h"
#include "network_state.h"
#include "node/rpc/json_rpc.h"
#include "node_to_node.h"
#include "notifier.h"
#include "rpc/frontend.h"
#include "rpc/member_frontend.h"
#include "rpc/serialization.h"
#include "secret_share.h"
#include "share_manager.h"
#include "timer.h"
#include "tls/25519.h"
#include "tls/client.h"
#include "tls/entropy.h"

#ifdef USE_NULL_ENCRYPTOR
#  include "kv/test/null_encryptor.h"
#endif

#ifndef VIRTUAL_ENCLAVE
#  include "ccf_t.h"
#endif

#include <atomic>
#include <chrono>
#define FMT_HEADER_ONLY
#include <fmt/format.h>
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
}

// Used by fmtlib to render ccf::State
namespace std
{
  std::ostream& operator<<(std::ostream& os, ccf::State s)
  {
    switch (s)
    {
      case ccf::State::uninitialized:
        return os << "uninitialized";
      case ccf::State::initialized:
        return os << "initialized";
      case ccf::State::pending:
        return os << "pending";
      case ccf::State::partOfPublicNetwork:
        return os << "partOfPublicNetwork";
      case ccf::State::partOfNetwork:
        return os << "partOfNetwork";
      case ccf::State::readingPublicLedger:
        return os << "readingPublicLedger";
      case ccf::State::readingPrivateLedger:
        return os << "readingPrivateLedger";
      default:
        return os << "unknown value";
    }
  }
}

namespace ccf
{
  using RaftConsensusType =
    raft::RaftConsensus<consensus::LedgerEnclave, NodeToNode>;
  using RaftType = raft::Raft<consensus::LedgerEnclave, NodeToNode>;
  using PbftConsensusType = pbft::Pbft<consensus::LedgerEnclave, NodeToNode>;

  template <typename T>
  class StateMachine
  {
    std::atomic<T> s;

  public:
    StateMachine(T s) : s(s) {}
    void expect(T s) const
    {
      auto state = this->s.load();
      if (s != state)
      {
        throw std::logic_error(
          fmt::format("State is {}, but expected {}", state, s));
      }
    }

    bool check(T s) const
    {
      return s == this->s.load();
    }

    void advance(T s)
    {
      LOG_DEBUG_FMT("Advancing to state {} (from {})", s, this->s.load());
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

    //
    // this node's core state
    //
    StateMachine<State> sm;
    SpinLock lock;

    NodeId self;
    tls::KeyPairPtr node_sign_kp;
    tls::KeyPairPtr node_encrypt_kp;
    std::vector<uint8_t> node_cert;
    std::vector<uint8_t> quote;
    CodeDigest node_code_id;

    //
    // kv store, replication, and I/O
    //
    ringbuffer::AbstractWriterFactory& writer_factory;
    ringbuffer::WriterPtr to_host;
    consensus::Config consensus_config;

    NetworkState& network;

    std::shared_ptr<kv::Consensus> consensus;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    std::shared_ptr<NodeToNode> n2n_channels;
    std::shared_ptr<Forwarder<NodeToNode>> cmd_forwarder;
    std::shared_ptr<enclave::RPCSessions> rpcsessions;
    ccf::Notifier& notifier;
    Timers& timers;

    std::shared_ptr<kv::TxHistory> history;
    std::shared_ptr<kv::AbstractTxEncryptor> encryptor;

    ShareManager share_manager;

    //
    // join protocol
    //
    std::shared_ptr<Timer> join_timer;

    //
    // recovery
    //
    NodeInfoNetwork node_info_network;
    std::shared_ptr<kv::Store> recovery_store;
    std::shared_ptr<kv::TxHistory> recovery_history;
    std::shared_ptr<kv::AbstractTxEncryptor> recovery_encryptor;
    kv::Version recovery_v;
    crypto::Sha256Hash recovery_root;
    std::vector<kv::Version> term_history;
    kv::Version last_recovered_commit_idx = 1;
    std::list<RecoveredLedgerSecret> recovery_ledger_secrets;

    consensus::Index ledger_idx = 0;

  public:
    NodeState(
      ringbuffer::AbstractWriterFactory& writer_factory,
      NetworkState& network,
      std::shared_ptr<enclave::RPCSessions> rpcsessions,
      ccf::Notifier& notifier,
      Timers& timers,
      ShareManager& share_manager) :
      sm(State::uninitialized),
      self(INVALID_ID),
      node_sign_kp(tls::make_key_pair()),
      node_encrypt_kp(tls::make_key_pair()),
      writer_factory(writer_factory),
      to_host(writer_factory.create_writer_to_outside()),
      network(network),
      rpcsessions(rpcsessions),
      notifier(notifier),
      timers(timers),
      share_manager(share_manager)
    {
      ::EverCrypt_AutoConfig2_init();
    }

    //
    // funcs in state "uninitialized"
    //
    void initialize(
      const consensus::Config& consensus_config_,
      std::shared_ptr<NodeToNode> n2n_channels_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      std::shared_ptr<Forwarder<NodeToNode>> cmd_forwarder_)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::uninitialized);

      consensus_config = consensus_config_;
      n2n_channels = n2n_channels_;
      // Capture rpc_map to pass to pbft for frontend execution
      rpc_map = rpc_map_;
      cmd_forwarder = cmd_forwarder_;
      sm.advance(State::initialized);
    }

    //
    // funcs in state "initialized"
    //
    auto create(const CreateNew::In& args)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::initialized);

      create_node_cert(args.config);
      open_node_frontend();

#ifdef GET_QUOTE
      if (network.consensus_type != ConsensusType::PBFT)
      {
        auto quote_opt = QuoteGenerator::get_quote(node_cert);
        if (!quote_opt.has_value())
        {
          return Fail<CreateNew::Out>("Quote could not be retrieved");
        }
        quote = quote_opt.value();
        auto node_code_id_opt = QuoteGenerator::get_code_id(quote);
        if (!node_code_id_opt.has_value())
        {
          return Fail<CreateNew::Out>(
            "Code ID could not be retrieved from quote");
        }
        node_code_id = node_code_id_opt.value();
      }
#endif

      switch (args.start_type)
      {
        case StartType::New:
        {
          network.identity =
            std::make_unique<NetworkIdentity>("CN=CCF Network");

          network.ledger_secrets = std::make_shared<LedgerSecrets>();
          network.ledger_secrets->init();

          network.encryption_key = std::make_unique<NetworkEncryptionKey>(
            tls::create_entropy()->random(crypto::BoxKey::KEY_SIZE));

          self = 0; // The first node id is always 0

          setup_encryptor(network.consensus_type);
          setup_consensus(network.consensus_type, args.config);
          setup_history();

          // Become the primary and force replication
          consensus->force_become_primary();

          // Open member frontend for members to configure and open the
          // network
          open_member_frontend();

          if (!create_and_send_request(args, quote))
          {
            return Fail<CreateNew::Out>(
              "Genesis transaction could not be committed");
          }

          accept_network_tls_connections(args.config);

          reset_quote();
          sm.advance(State::partOfNetwork);

          return Success<CreateNew::Out>(
            {node_cert,
             network.identity->cert,
             get_network_encryption_key_public_pem()});
        }
        case StartType::Join:
        {
          // TLS connections are not endorsed by the network until the node
          // has joined
          accept_node_tls_connections();

          sm.advance(State::pending);

          return Success<CreateNew::Out>({node_cert});
        }
        case StartType::Recover:
        {
          node_info_network = args.config.node_info_network;

          network.identity =
            std::make_unique<NetworkIdentity>("CN=CCF Network");
          network.ledger_secrets = std::make_shared<LedgerSecrets>();
          network.encryption_key = std::make_unique<NetworkEncryptionKey>(
            tls::create_entropy()->random(crypto::BoxKey::KEY_SIZE));

          setup_history();

          // It is necessary to give an encryptor to the store for it to
          // deserialise the public domain when recovering the public ledger.
          // Once the public recovery is complete, the existing encryptor is
          // replaced with a new one initialised with recovered ledger secrets.
          setup_encryptor(network.consensus_type);

          setup_recovery_hook();

          accept_network_tls_connections(args.config);

          sm.advance(State::readingPublicLedger);

          return Success<CreateNew::Out>(
            {node_cert,
             network.identity->cert,
             get_network_encryption_key_public_pem()});
        }
        default:
        {
          throw std::logic_error(fmt::format(
            "Node was started in unknown mode {}", args.start_type));
        }
      }
    }

    //
    // funcs in state "pending"
    //
    void initiate_join(const Join::In& args)
    {
      auto network_ca =
        std::make_shared<tls::CA>(args.config.joining.network_cert);
      auto join_client_cert = std::make_unique<tls::Cert>(
        network_ca, node_cert, node_sign_kp->private_key_pem());

      // Create RPC client and connect to remote node
      auto join_client =
        rpcsessions->create_client(std::move(join_client_cert));

      join_client->connect(
        args.config.joining.target_host,
        args.config.joining.target_port,
        [this, args](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          std::lock_guard<SpinLock> guard(lock);
          if (!sm.check(State::pending))
          {
            return false;
          }

          if (status != HTTP_STATUS_OK)
          {
            LOG_FAIL_FMT(
              "An error occurred while joining the network: {} {}{}",
              status,
              http_status_str(status),
              data.empty() ?
                "" :
                fmt::format("  '{}'", std::string(data.begin(), data.end())));
            return false;
          }

          auto j = jsonrpc::unpack(data, jsonrpc::Pack::Text);

          JoinNetworkNodeToNode::Out resp;
          try
          {
            resp = j.get<JoinNetworkNodeToNode::Out>();
          }
          catch (const std::exception& e)
          {
            LOG_FAIL_FMT(
              "An error occurred while parsing the join network response");
            LOG_DEBUG_FMT(
              "An error occurred while parsing the join network response: {}",
              j.dump());
            return false;
          }

          // Set network secrets, node id and become part of network.
          if (resp.node_status == NodeStatus::TRUSTED)
          {
            network.identity =
              std::make_unique<NetworkIdentity>(resp.network_info.identity);
            network.ledger_secrets =
              std::make_shared<LedgerSecrets>(resp.network_info.ledger_secrets);
            network.encryption_key = std::make_unique<NetworkEncryptionKey>(
              std::move(resp.network_info.encryption_key));

            self = resp.node_id;

            if (resp.consensus_type != network.consensus_type)
            {
              throw std::logic_error(fmt::format(
                "Enclave initiated with consensus type {} but target node "
                "responded with consensus {}",
                network.consensus_type,
                resp.consensus_type));
            }

            setup_encryptor(resp.consensus_type);
            setup_consensus(resp.consensus_type, args.config, resp.public_only);
            setup_history();

            open_member_frontend();

            accept_network_tls_connections(args.config);

            if (resp.public_only)
            {
              last_recovered_commit_idx = resp.last_recovered_commit_idx;
              setup_recovery_hook();
              sm.advance(State::partOfPublicNetwork);
            }
            else
            {
              reset_quote();
              sm.advance(State::partOfNetwork);
            }

            join_timer.reset();

            LOG_INFO_FMT(
              "Node has now joined the network as node {}: {}",
              self,
              (resp.public_only ? "public only" : "all domains"));
          }
          else if (resp.node_status == NodeStatus::PENDING)
          {
            LOG_INFO_FMT(
              "Node {} is waiting for votes of members to be trusted",
              resp.node_id);
          }

          return true;
        });

      // Send RPC request to remote node to join the network.
      JoinNetworkNodeToNode::In join_params;

      join_params.node_info_network = args.config.node_info_network;
      join_params.public_encryption_key =
        node_encrypt_kp->public_key_pem().raw();
      join_params.quote = quote;
      join_params.consensus_type = network.consensus_type;

      LOG_DEBUG_FMT(
        "Sending join request to {}:{}",
        args.config.joining.target_host,
        args.config.joining.target_port);

      const auto body = jsonrpc::pack(join_params, jsonrpc::Pack::Text);

      http::Request r(fmt::format(
        "/{}/{}", ccf::get_actor_prefix(ccf::ActorsType::nodes), "join"));
      r.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
      r.set_body(&body);

      join_client->send_request(r.build_request());
    }

    void join(const Join::In& args)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::pending);

      initiate_join(args);

      join_timer = timers.new_timer(
        std::chrono::milliseconds(args.config.joining.join_timer),
        [this, args]() {
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
        kv::Tx tx;
        GenesisGenerator g(network, tx);
        auto last_sig = g.get_last_signature();
        if (last_sig.has_value())
        {
          LOG_DEBUG_FMT(
            "Read signature at {} for view {}", ledger_idx, last_sig->view);
          // Initial transactions, before the first signature, must have
          // happened in the first signature's view (eg - if the first
          // signature is at seqno 20 in view 4, then transactions 1->19 must
          // also have been in view 4). The brief justification is that while
          // the first node may start in an arbitrarily high view (it does not
          // necessarily start in view 1), it cannot _change_ view before a
          // valid signature.
          const auto term_start_idx =
            term_history.empty() ? 1 : last_recovered_commit_idx + 1;
          for (auto i = term_history.size(); i < last_sig->view; ++i)
          {
            term_history.push_back(term_start_idx);
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
      network.tables->rollback(last_recovered_commit_idx);
      ledger_truncate(last_recovered_commit_idx);
      LOG_INFO_FMT(
        "End of public ledger recovery - Truncating ledger to last signed "
        "index: {}",
        last_recovered_commit_idx);

      network.ledger_secrets->init(last_recovered_commit_idx + 1);
      setup_encryptor(network.consensus_type);
      // KV term must be set before the first Tx is committed
      LOG_INFO_FMT(
        "Setting term on public recovery KV to {}", term_history.size() + 2);
      network.tables->set_term(term_history.size() + 2);

      kv::Tx tx;
      GenesisGenerator g(network, tx);
      g.create_service(network.identity->cert, last_recovered_commit_idx + 1);
      g.retire_active_nodes();

      self = g.add_node({node_info_network,
                         node_cert,
                         quote,
                         node_encrypt_kp->public_key_pem().raw(),
                         NodeStatus::PENDING});

      LOG_INFO_FMT("Deleted previous nodes and added self as {}", self);

      kv::Version index = 0;
      kv::Term term = 0;
      kv::Version global_commit = 0;

      auto ls = g.get_last_signature();
      if (ls.has_value())
      {
        auto s = ls.value();
        index = s.seqno;
        term = s.view;
        global_commit = s.commit_seqno;
      }

      auto h = dynamic_cast<MerkleTxHistory*>(history.get());
      if (h)
      {
        h->set_node_id(self);
      }

      setup_raft(true);

      LOG_DEBUG_FMT(
        "Restarting consensus at view: {} seqno: {} commit_seqno {}",
        term,
        index,
        global_commit);
      consensus->force_become_primary(index, term, term_history, index);

      // Sets itself as trusted
      g.trust_node(self);

#ifdef GET_QUOTE
      if (network.consensus_type != ConsensusType::PBFT)
      {
        g.trust_node_code_id(node_code_id);
      }
#endif

      if (g.finalize() != kv::CommitSuccess::OK)
      {
        throw std::logic_error(
          "Could not commit transaction when starting recovered public "
          "network");
      }

      open_member_frontend();

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
      {
        recovery_store->compact(ledger_idx);
      }

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
      // When reaching the end of the private ledger, make sure the same
      // ledger has been read and swap in private state

      sm.expect(State::readingPrivateLedger);

      if (recovery_v != recovery_store->current_version())
      {
        throw std::logic_error(fmt::format(
          "Private recovery did not reach public ledger version: {}/{}",
          recovery_store->current_version(),
          recovery_v));
      }

      auto h = dynamic_cast<MerkleTxHistory*>(recovery_history.get());
      if (h->get_replicated_state_root() != recovery_root)
      {
        throw std::logic_error(fmt::format(
          "Root of public store does not match root of private store at {}",
          recovery_v));
      }

      network.tables->swap_private_maps(*recovery_store.get());
      recovery_store.reset();
      reset_recovery_hook();

      // Raft should deserialise all security domains when network is opened
      consensus->enable_all_domains();

      // Open the service
      if (consensus->is_primary())
      {
        kv::Tx tx;

        // Shares for the new ledger secret can only be issued now, once the
        // previous ledger secrets have been recovered
        share_manager.issue_shares_on_recovery(
          tx, last_recovered_commit_idx + 1);
        GenesisGenerator g(network, tx);
        if (!g.open_service())
        {
          throw std::logic_error("Service could not be opened");
        }

        if (g.finalize() != kv::CommitSuccess::OK)
        {
          throw std::logic_error(
            "Could not commit transaction when finishing network recovery");
        }
      }

      reset_quote();
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
      recovery_store = std::make_shared<kv::Store>();
      recovery_store->clone_schema(*network.tables);
      Signatures* recovery_signature_map =
        recovery_store->get<Signatures>(Tables::SIGNATURES);
      Nodes* recovery_nodes_map = recovery_store->get<Nodes>(Tables::NODES);

      recovery_history = std::make_shared<MerkleTxHistory>(
        *recovery_store.get(),
        self,
        *node_sign_kp,
        *recovery_signature_map,
        *recovery_nodes_map);

#ifdef USE_NULL_ENCRYPTOR
      recovery_encryptor = std::make_shared<kv::NullTxEncryptor>();
#else
      if (network.consensus_type == ConsensusType::PBFT)
      {
        recovery_encryptor =
          std::make_shared<PbftTxEncryptor>(network.ledger_secrets, true);
      }
      else if (network.consensus_type == ConsensusType::RAFT)
      {
        recovery_encryptor =
          std::make_shared<RaftTxEncryptor>(network.ledger_secrets, true);
        recovery_encryptor->set_iv_id(self); // RaftEncryptor uses node ID as iv
      }
      else
      {
        throw std::logic_error(
          "Unknown consensus type " + std::to_string(network.consensus_type));
      }
#endif

      recovery_store->set_history(recovery_history);
      recovery_store->set_encryptor(recovery_encryptor);

      // Record real store version and root
      recovery_v = network.tables->current_version();
      auto h = dynamic_cast<MerkleTxHistory*>(history.get());
      recovery_root = h->get_replicated_state_root();

      LOG_DEBUG_FMT("Recovery store successfully setup: {}", recovery_v);
    }

    bool accept_recovery(kv::Tx& tx) override
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::partOfPublicNetwork);

      GenesisGenerator g(network, tx);
      share_manager.clear_submitted_recovery_shares(tx);
      return g.service_wait_for_shares();
    }

    void initiate_private_recovery(kv::Tx& tx) override
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::partOfPublicNetwork);

      auto restored_versions =
        share_manager.restore_recovery_shares_info(tx, recovery_ledger_secrets);

      LOG_INFO_FMT("Initiating end of recovery (primary)");

      // Emit signature to certify transactions that happened on public
      // network
      history->emit_signature();

      for (auto const& v : restored_versions)
      {
        broadcast_ledger_secret(
          tx, network.ledger_secrets->get_secret(v).value(), v, true);
      }

      // Setup new temporary store and record current version/root
      setup_private_recovery_store();

      // Start reading private security domain of ledger
      ledger_idx = 0;
      read_ledger_idx(++ledger_idx);

      recovery_ledger_secrets.clear();
      sm.advance(State::readingPrivateLedger);
    }

    //
    // funcs in state "partOfNetwork" or "partOfPublicNetwork"
    //
    void tick(std::chrono::milliseconds elapsed)
    {
      if (
        !sm.check(State::partOfNetwork) &&
        !sm.check(State::partOfPublicNetwork) &&
        !sm.check(State::readingPrivateLedger))
      {
        return;
      }

      consensus->periodic(elapsed);
    }

    void tick_end()
    {
      if (
        !sm.check(State::partOfNetwork) &&
        !sm.check(State::partOfPublicNetwork) &&
        !sm.check(State::readingPrivateLedger))
      {
        return;
      }

      consensus->periodic_end();
    }

    void node_msg(const std::vector<uint8_t>& data)
    {
      // Only process messages once part of network
      if (
        !sm.check(State::partOfNetwork) &&
        !sm.check(State::partOfPublicNetwork) &&
        !sm.check(State::readingPrivateLedger))
      {
        return;
      }

      OArray oa(std::move(data));

      Header header;
      NodeMsgType msg_type =
        serialized::overlay<NodeMsgType>(oa.data(), oa.size());

      switch (msg_type)
      {
        case channel_msg:
          n2n_channels->recv_message(std::move(oa));
          break;
        case consensus_msg:
          consensus->recv_message(std::move(oa));
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
         sm.check(State::partOfPublicNetwork) ||
         sm.check(State::readingPrivateLedger)) &&
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

    bool rekey_ledger(kv::Tx& tx) override
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::partOfNetwork);

      // Because submitted recovery shares are encrypted with the latest ledger
      // secret, it is not possible to rekey the ledger if the service is in
      // that state.
      GenesisGenerator g(network, tx);
      if (
        g.get_service_status().value() ==
        ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
      {
        LOG_FAIL_FMT(
          "Cannot rekey ledger while the service is waiting for recovery "
          "shares");
        return false;
      }

      // Effects of ledger rekey are only observed from the next transaction,
      // once the local hook on the secrets table has been triggered.

      auto new_ledger_secret = LedgerSecret();
      share_manager.issue_shares_on_rekey(tx, new_ledger_secret);
      broadcast_ledger_secret(tx, new_ledger_secret);

      return true;
    }

    void node_quotes(
      kv::ReadOnlyTx& tx,
      GetQuotes::Out& result,
      const std::optional<std::set<NodeId>>& filter) override
    {
      auto nodes_view = tx.get_read_only_view(network.nodes);

      nodes_view->foreach([&result, &filter, this](
                            const NodeId& nid, const NodeInfo& ni) {
        if (!filter.has_value() || (filter->find(nid) != filter->end()))
        {
          if (ni.status == ccf::NodeStatus::TRUSTED)
          {
            GetQuotes::Quote q;
            q.node_id = nid;
            q.raw = fmt::format("{:02x}", fmt::join(ni.quote, ""));

#ifdef GET_QUOTE
            if (this->network.consensus_type != ConsensusType::PBFT)
            {
              auto code_id_opt = QuoteGenerator::get_code_id(ni.quote);
              if (!code_id_opt.has_value())
              {
                q.error = fmt::format("Failed to retrieve code ID from quote");
              }
              else
              {
                q.mrenclave =
                  fmt::format("{:02x}", fmt::join(code_id_opt.value(), ""));
              }
            }
#endif
            result.quotes.push_back(q);
          }
        }
        return true;
      });
    };

    NodeId get_node_id() const override
    {
      return self;
    }

  private:
    tls::SubjectAltName get_subject_alt_name(const CCFConfig& config)
    {
      // If a domain is passed at node creation, record domain in SAN for node
      // hostname authentication over TLS. Otherwise, record IP in SAN.
      bool san_is_ip = config.domain.empty();
      return {san_is_ip ? config.node_info_network.rpchost : config.domain,
              san_is_ip};
    }

    void create_node_cert(const CCFConfig& config)
    {
      node_cert =
        node_sign_kp->self_sign("CN=CCF node", get_subject_alt_name(config));
    }

    void accept_node_tls_connections()
    {
      // Accept TLS connections, presenting self-signed (i.e. non-endorsed) node
      // certificate. Once the node is part of the network, this certificate
      // should be replaced with network-endorsed counterpart
      rpcsessions->set_cert(node_cert, node_sign_kp->private_key_pem());
      LOG_INFO_FMT("Node TLS connections now accepted");
    }

    void accept_network_tls_connections(const CCFConfig& config)
    {
      // Accept TLS connections, presenting node certificate signed by network
      // certificate
      auto nw = tls::make_key_pair({network.identity->priv_key});

      auto endorsed_node_cert = nw->sign_csr(
        node_sign_kp->create_csr(fmt::format("CN=CCF node {}", self)),
        fmt::format("CN={}", "CCF Network"),
        get_subject_alt_name(config));

      rpcsessions->set_cert(
        endorsed_node_cert, node_sign_kp->private_key_pem());
      LOG_INFO_FMT("Network TLS connections now accepted");
    }

    void open_frontend(ccf::ActorsType actor)
    {
      auto fe = rpc_map->find(actor);
      if (!fe.has_value())
      {
        throw std::logic_error(
          fmt::format("Cannot open {} frontend", (int)actor));
      }
      fe.value()->open();
    }

    void open_node_frontend()
    {
      open_frontend(ActorsType::nodes);
    }

    void open_member_frontend()
    {
      open_frontend(ActorsType::members);
    }

    void open_user_frontend()
    {
      open_frontend(ActorsType::users);
    }

    void broadcast_ledger_secret(
      kv::Tx& tx,
      const LedgerSecret& secret,
      kv::Version version = kv::NoVersion,
      bool exclude_self = false)
    {
      GenesisGenerator g(network, tx);
      auto secrets_view = tx.get_view(network.secrets);

      auto trusted_nodes = g.get_trusted_nodes(
        exclude_self ? std::make_optional(self) : std::nullopt);

      ccf::EncryptedLedgerSecrets secret_set;
      secret_set.primary_public_encryption_key =
        node_encrypt_kp->public_key_pem().raw();

      for (auto [nid, ni] : trusted_nodes)
      {
        ccf::EncryptedLedgerSecret secret_for_node;
        secret_for_node.node_id = nid;

        // Encrypt secrets with a shared secret derived from backup public
        // key
        auto backup_pubk = tls::make_public_key(ni.encryption_pub_key);
        crypto::KeyAesGcm backup_shared_secret(
          tls::KeyExchangeContext(node_encrypt_kp, backup_pubk)
            .compute_shared_secret());

        crypto::GcmCipher gcmcipher(secret.master.size());
        auto iv = tls::create_entropy()->random(gcmcipher.hdr.get_iv().n);
        std::copy(iv.begin(), iv.end(), gcmcipher.hdr.iv);

        backup_shared_secret.encrypt(
          iv, secret.master, nullb, gcmcipher.cipher.data(), gcmcipher.hdr.tag);

        secret_for_node.encrypted_secret = gcmcipher.serialise();
        secret_set.secrets.emplace_back(std::move(secret_for_node));
      }

      secrets_view->put(version, secret_set);
    }

    std::vector<uint8_t> serialize_create_request(
      const CreateNew::In& args, const std::vector<uint8_t>& quote)
    {
      CreateNetworkNodeToNode::In create_params;

      for (auto& m_info : args.config.genesis.members_info)
      {
        create_params.members_info.push_back(m_info);
      }

      create_params.gov_script = args.config.genesis.gov_script;
      create_params.node_cert = node_cert;
      create_params.network_cert = network.identity->cert;
      create_params.quote = quote;
      create_params.public_encryption_key =
        node_encrypt_kp->public_key_pem().raw();
      create_params.code_digest =
        std::vector<uint8_t>(std::begin(node_code_id), std::end(node_code_id));
      create_params.node_info_network = args.config.node_info_network;
      create_params.consensus_type = network.consensus_type;
      create_params.recovery_threshold = args.config.genesis.recovery_threshold;

      const auto body = jsonrpc::pack(create_params, jsonrpc::Pack::Text);

      http::Request request(fmt::format(
        "/{}/{}", ccf::get_actor_prefix(ccf::ActorsType::members), "create"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      request.set_body(&body);
      http::sign_request(request, node_sign_kp);

      return request.build_request();
    }

    bool parse_create_response(const std::vector<uint8_t>& response)
    {
      http::SimpleResponseProcessor processor;
      http::ResponseParser parser(processor);

      const auto parsed_count =
        parser.execute(response.data(), response.size());
      if (parsed_count != response.size())
      {
        LOG_FAIL_FMT(
          "Tried to parse {} response bytes, actually parsed {}",
          response.size(),
          parsed_count);
        return false;
      }

      if (processor.received.size() != 1)
      {
        LOG_FAIL_FMT(
          "Expected single message, found {}", processor.received.size());
        return false;
      }

      const auto& r = processor.received.front();

      if (r.status != HTTP_STATUS_OK)
      {
        LOG_FAIL_FMT(
          "Create response is error: {} {}",
          r.status,
          http_status_str(r.status));
        return false;
      }

      const auto body = jsonrpc::unpack(r.body, jsonrpc::Pack::Text);
      if (!body.is_boolean())
      {
        LOG_FAIL_FMT("Expected boolean body in create response");
        LOG_DEBUG_FMT(
          "Expected boolean body in create response: {}", body.dump());
        return false;
      }

      return body;
    }

    bool send_create_request(const std::vector<uint8_t>& packed)
    {
      auto node_session = std::make_shared<enclave::SessionContext>(
        enclave::InvalidSessionId, node_cert);
      auto ctx = enclave::make_rpc_context(node_session, packed);

      ctx->is_create_request = true;

      const auto actor_opt = http::extract_actor(*ctx);
      if (!actor_opt.has_value())
      {
        throw std::logic_error("Unable to get actor for create request");
      }

      std::string preferred_actor_name;
      const auto actor =
        rpc_map->resolve(actor_opt.value(), preferred_actor_name);
      auto frontend_opt = this->rpc_map->find(actor);
      if (!frontend_opt.has_value())
      {
        throw std::logic_error(
          "RpcMap::find returned invalid (empty) frontend");
      }
      auto frontend = frontend_opt.value();

      const auto response = frontend->process(ctx);
      if (!response.has_value())
      {
        return false;
      }

      return parse_create_response(response.value());
    }

    bool create_and_send_request(
      const CreateNew::In& args, const std::vector<uint8_t>& quote)
    {
      const auto create_success =
        send_create_request(serialize_create_request(args, quote));
      if (network.consensus_type == ConsensusType::PBFT)
      {
        return true;
      }
      else
      {
        return create_success;
      }
    }

    std::vector<uint8_t> get_network_encryption_key_public_pem()
    {
      return tls::PublicX25519::write(crypto::BoxKey::public_from_private(
                                        network.encryption_key->private_raw))
        .raw();
    }

    void reset_quote()
    {
      quote.clear();
      quote.shrink_to_fit();
    }

    void backup_finish_recovery()
    {
      if (!consensus->is_backup())
        return;

      sm.expect(State::partOfPublicNetwork);

      LOG_INFO_FMT("Initiating end of recovery (backup)");

      // Setup new temporary store and record current version/root
      setup_private_recovery_store();

      // Start reading private security domain of ledger
      ledger_idx = 0;
      read_ledger_idx(++ledger_idx);

      sm.advance(State::readingPrivateLedger);
    }

    void setup_basic_hooks()
    {
      network.service.set_global_hook(
        [this](kv::Version version, const Service::Write& w) {
          const auto it = w.find(0);
          if (it == w.end() || !it->second.has_value())
          {
            throw std::logic_error(
              "Unexpected: write to service table does not include key 0");
          }

          if (
            it->second.value().status == ServiceStatus::OPEN &&
            !this->is_part_of_public_network())
          {
            this->consensus->set_f(1);
            open_user_frontend();
            LOG_INFO_FMT("Network is OPEN, now accepting user transactions");
          }
        });

      network.secrets.set_local_hook([this](
                                       kv::Version version,
                                       const Secrets::Write& w) {
        bool has_secrets = false;
        std::list<LedgerSecrets::VersionedLedgerSecret> restored_secrets;

        for (const auto& [v, opt_secret_set] : w)
        {
          if (!opt_secret_set.has_value())
          {
            throw std::logic_error(
              fmt::format("Unexpected: removal from secrets table ({})", v));
          }

          const auto& secret_set = opt_secret_set.value();

          for (auto& encrypted_secret_for_node : secret_set.secrets)
          {
            if (encrypted_secret_for_node.node_id == self)
            {
              crypto::GcmCipher gcmcipher;
              gcmcipher.deserialise(encrypted_secret_for_node.encrypted_secret);
              std::vector<uint8_t> plain_secret(gcmcipher.cipher.size());

              auto primary_pubk =
                tls::make_public_key(secret_set.primary_public_encryption_key);

              crypto::KeyAesGcm primary_shared_key(
                tls::KeyExchangeContext(node_encrypt_kp, primary_pubk)
                  .compute_shared_secret());

              if (!primary_shared_key.decrypt(
                    gcmcipher.hdr.get_iv(),
                    gcmcipher.hdr.tag,
                    gcmcipher.cipher,
                    nullb,
                    plain_secret.data()))
              {
                throw std::logic_error(
                  "Decryption of past network secrets failed");
              }

              has_secrets = true;

              // If the version key is NoVersion, we are rekeying. Use the
              // version passed to the hook instead. For recovery, the version
              // of the past secrets is passed as the key.
              kv::Version secret_version = (v == kv::NoVersion) ? version : v;

              if (is_part_of_public_network())
              {
                restored_secrets.push_back(
                  {secret_version, LedgerSecret(plain_secret)});
              }
              else
              {
                // When rekeying, set the encryption key for the next version
                // onward (for the backups to deserialise this transaction
                // with the old key). The encryptor is in charge of updating
                // the ledger secrets on global commit.
                encryptor->update_encryption_key(
                  secret_version + 1, plain_secret);
              }
            }
          }
        }

        // When recovering, trigger end of recovery protocol
        if (has_secrets && is_part_of_public_network())
        {
          restored_secrets.sort(
            [](
              const LedgerSecrets::VersionedLedgerSecret& a,
              const LedgerSecrets::VersionedLedgerSecret& b) {
              return a.version < b.version;
            });

          network.ledger_secrets->restore(std::move(restored_secrets));
          backup_finish_recovery();
        }
      });
    }

    kv::Version get_last_recovered_commit_idx() override
    {
      // On recovery, only one node recovers the public ledger and is thus aware
      // of the version at which the new ledger secret is applicable from. If
      // the primary changes while the network is public-only, the new primary
      // should also know at which version the new ledger secret is applicable
      // from.
      std::lock_guard<SpinLock> guard(lock);
      return last_recovered_commit_idx;
    }

    void setup_recovery_hook()
    {
      static bool is_first_shares = true;

      network.shares.set_local_hook(
        [this](kv::Version version, const Shares::Write& w) {
          for (const auto& [k, opt_v] : w)
          {
            if (!opt_v.has_value())
            {
              throw std::logic_error(
                fmt::format("Unexpected: removal from shares table ({})", k));
            }

            const auto& v = opt_v.value();

            kv::Version ledger_secret_version;
            if (is_first_shares)
            {
              // Special case for the first recovery share issuing (at network
              // open), which is applicable from the very first transaction
              ledger_secret_version = 1;
              is_first_shares = false;
            }
            else
            {
              // If the version is not set (rekeying), use the version
              // from the hook plus one. Otherwise (recovery), use the
              // version specified.
              ledger_secret_version =
                v.wrapped_latest_ledger_secret.version == kv::NoVersion ?
                (version + 1) :
                v.wrapped_latest_ledger_secret.version;
            }

            // No encrypted ledger secret are stored in the case of a pure
            // re-share (i.e. no ledger rekey).
            if (
              !v.encrypted_previous_ledger_secret.empty() ||
              ledger_secret_version == 1)
            {
              LOG_TRACE_FMT(
                "Adding one encrypted recovery ledger secret at {}",
                ledger_secret_version);

              recovery_ledger_secrets.push_back(
                {ledger_secret_version, v.encrypted_previous_ledger_secret});
            }
          }
        });
    }

    void reset_recovery_hook()
    {
      network.shares.unset_local_hook();
    }

    void setup_n2n_channels()
    {
      n2n_channels->initialize(self, {network.identity->priv_key});
    }

    void setup_cmd_forwarder()
    {
      cmd_forwarder->initialize(self);
    }

    void setup_raft(bool public_only = false)
    {
      setup_n2n_channels();
      setup_cmd_forwarder();

      auto raft = std::make_unique<RaftType>(
        std::make_unique<raft::Adaptor<kv::Store, kv::DeserialiseSuccess>>(
          network.tables),
        std::make_unique<consensus::LedgerEnclave>(writer_factory),
        n2n_channels,
        self,
        std::chrono::milliseconds(consensus_config.raft_request_timeout),
        std::chrono::milliseconds(consensus_config.raft_election_timeout),
        public_only);

      consensus = std::make_shared<RaftConsensusType>(std::move(raft));

      network.tables->set_consensus(consensus);

      notifier.set_consensus(consensus);

      // When a node is added, even locally, inform the host so that it can
      // map the node id to a hostname and service and inform raft so that it
      // can add a new active configuration.
      network.nodes.set_local_hook(
        [this](kv::Version version, const Nodes::Write& w) {
          bool configure = false;
          auto configuration = consensus->get_latest_configuration();

          for (const auto& [node_id, opt_ni] : w)
          {
            if (!opt_ni.has_value())
            {
              throw std::logic_error(fmt::format(
                "Unexpected: removal from nodes table ({})", node_id));
            }

            const auto& ni = opt_ni.value();
            switch (ni.status)
            {
              case NodeStatus::PENDING:
              {
                // Pending nodes are not added to consensus until they are
                // trusted
                break;
              }
              case NodeStatus::TRUSTED:
              {
                configuration.try_emplace(node_id, ni.nodehost, ni.nodeport);
                configure = true;
                break;
              }
              case NodeStatus::RETIRED:
              {
                configuration.erase(node_id);
                configure = true;
                break;
              }
              default:
              {}
            }
          }

          if (configure)
          {
            consensus->add_configuration(version, configuration);
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
        *node_sign_kp,
        network.signatures,
        network.nodes);

      network.tables->set_history(history);
    }

    void setup_encryptor(ConsensusType consensus_type)
    {
      // This function makes use of network secrets and should be called once
      // the node has joined the service (either via start_network() or
      // join_network())
#ifdef USE_NULL_ENCRYPTOR
      encryptor = std::make_shared<kv::NullTxEncryptor>();
#else
      if (network.consensus_type == ConsensusType::PBFT)
      {
        encryptor = std::make_shared<PbftTxEncryptor>(network.ledger_secrets);
      }
      else if (network.consensus_type == ConsensusType::RAFT)
      {
        encryptor = std::make_shared<RaftTxEncryptor>(network.ledger_secrets);
        encryptor->set_iv_id(self); // RaftEncryptor uses node ID as iv
      }
      else
      {
        throw std::logic_error(
          "Unknown consensus type " + std::to_string(consensus_type));
      }
#endif

      network.tables->set_encryptor(encryptor);
    }

    void setup_consensus(
      ConsensusType consensus_type,
      const CCFConfig& config,
      bool public_only = false)
    {
      if (consensus_type == ConsensusType::PBFT)
      {
        setup_pbft(config);
      }
      else if (consensus_type == ConsensusType::RAFT)
      {
        setup_raft(public_only);
      }
      else
      {
        throw std::logic_error(
          "Unknown consensus type " + std::to_string(consensus_type));
      }
    }

    void read_ledger_idx(consensus::Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(
        consensus::ledger_get,
        to_host,
        idx,
        consensus::LedgerRequestPurpose::Recovery);
    }

    void ledger_truncate(consensus::Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(consensus::ledger_truncate, to_host, idx);
    }

    void setup_pbft(const CCFConfig& config)
    {
      setup_n2n_channels();

      consensus = std::make_shared<PbftConsensusType>(
        std::make_unique<pbft::Adaptor<kv::Store, kv::DeserialiseSuccess>>(
          network.tables),
        n2n_channels,
        self,
        config.signature_intervals.sig_max_tx,
        std::make_unique<consensus::LedgerEnclave>(writer_factory),
        rpc_map,
        rpcsessions,
        network.pbft_requests_map,
        network.pbft_pre_prepares_map,
        network.signatures,
        network.pbft_new_views_map,
        node_sign_kp->private_key_pem().str(),
        node_cert,
        consensus_config);

      network.tables->set_consensus(consensus);

      notifier.set_consensus(consensus);

      network.nodes.set_local_hook(
        [this](kv::Version version, const Nodes::Write& w) {
          for (const auto& [node_id, opt_ni] : w)
          {
            if (!opt_ni.has_value())
            {
              throw std::logic_error(fmt::format(
                "Unexpected: removal from nodes table ({})", node_id));
            }

            const auto& ni = opt_ni.value();
            n2n_channels->create_channel(node_id, ni.nodehost, ni.nodeport);

            pbft::Configuration::Nodes configuration;
            configuration[node_id] = {ni.nodehost, ni.nodeport, ni.cert};
            consensus->add_configuration(version, configuration);
          }
        });

      setup_basic_hooks();
    }
  };
}
