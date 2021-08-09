// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../tls/msg_types.h"
#include "tcp.h"

#include <unordered_map>

namespace asynchost
{
  class RPCConnections
  {
  private:
    class ClientBehaviour : public TCPBehaviour
    {
    public:
      RPCConnections& parent;
      int64_t id;

      ClientBehaviour(RPCConnections& parent, int64_t id) :
        parent(parent),
        id(id)
      {}

      void on_resolve_failed()
      {
        LOG_DEBUG_FMT("rpc resolve failed {}", id);
        cleanup();
      }

      void on_connect_failed()
      {
        LOG_DEBUG_FMT("rpc connect failed {}", id);
        cleanup();
      }

      void on_read(size_t len, uint8_t*& data)
      {
        LOG_DEBUG_FMT("rpc read {}: {}", id, len);

        RINGBUFFER_WRITE_MESSAGE(
          tls::tls_inbound,
          parent.to_enclave,
          id,
          serializer::ByteRange{data, len});
      }

      void on_disconnect()
      {
        LOG_DEBUG_FMT("rpc disconnect {}", id);
        cleanup();
      }

      void cleanup()
      {
        RINGBUFFER_WRITE_MESSAGE(tls::tls_close, parent.to_enclave, id);
      }
    };

    class RPCServerBehaviour : public TCPServerBehaviour
    {
    public:
      RPCConnections& parent;
      int64_t id;

      RPCServerBehaviour(RPCConnections& parent, int64_t id) :
        parent(parent),
        id(id)
      {}

      void on_listening(
        const std::string& host, const std::string& service) override
      {
        LOG_INFO_FMT("Listening for RPCs on {}:{}", host, service);
      }

      void on_accept(TCP& peer) override
      {
        auto client_id = parent.get_next_id();
        peer->set_behaviour(
          std::make_unique<ClientBehaviour>(parent, client_id));

        parent.sockets.emplace(client_id, peer);

        const auto listen_address = parent.get_address(id);
        LOG_DEBUG_FMT("rpc accept {} on {}", client_id, listen_address);

        RINGBUFFER_WRITE_MESSAGE(
          tls::tls_start, parent.to_enclave, client_id, listen_address);
      }

      void cleanup()
      {
        parent.sockets.erase(id);
      }
    };

    std::unordered_map<tls::ConnID, TCP> sockets;
    tls::ConnID next_id = 1;

    size_t client_connection_timeout;
    ringbuffer::WriterPtr to_enclave;

  public:
    RPCConnections(
      ringbuffer::AbstractWriterFactory& writer_factory,
      size_t client_connection_timeout_) :
      client_connection_timeout(client_connection_timeout_),
      to_enclave(writer_factory.create_writer_to_inside())
    {}

    bool listen(tls::ConnID id, std::string& host, std::string& service)
    {
      if (id == 0)
      {
        id = get_next_id();
      }

      if (sockets.find(id) != sockets.end())
      {
        LOG_FAIL_FMT("Cannot listen on id {}: already in use", id);
        return false;
      }

      TCP s;
      s->set_behaviour(std::make_unique<RPCServerBehaviour>(*this, id));

      if (!s->listen(host, service))
      {
        return false;
      }

      host = s->get_host();
      service = s->get_service();

      sockets.emplace(id, s);
      return true;
    }

    bool connect(
      int64_t id, const std::string& host, const std::string& service)
    {
      if (id == 0)
      {
        id = get_next_id();
      }

      if (sockets.find(id) != sockets.end())
      {
        LOG_FAIL_FMT("Cannot connect on id {}: already in use", id);
        return false;
      }

      auto s = TCP(true, client_connection_timeout);
      s->set_behaviour(std::make_unique<ClientBehaviour>(*this, id));

      if (!s->connect(host, service))
      {
        return false;
      }

      sockets.emplace(id, s);
      return true;
    }

    bool write(int64_t id, size_t len, const uint8_t* data)
    {
      auto s = sockets.find(id);

      if (s == sockets.end())
      {
        LOG_FAIL_FMT(
          "Received an outbound message for id {} which is not a known "
          "connection. Ignoring message of {} bytes",
          id,
          len);
        return false;
      }

      if (s->second.is_null())
        return false;

      return s->second->write(len, data);
    }

    bool stop(int64_t id)
    {
      // Invalidating the TCP socket will result in the handle being closed. No
      // more messages will be read from or written to the TCP socket.
      sockets[id] = nullptr;
      RINGBUFFER_WRITE_MESSAGE(tls::tls_close, to_enclave, id);

      return true;
    }

    bool close(int64_t id)
    {
      if (sockets.erase(id) < 1)
      {
        LOG_FAIL_FMT("Cannot close id {}: does not exist", id);
        return false;
      }

      return true;
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, tls::tls_outbound, [this](const uint8_t* data, size_t size) {
          auto [id, body] =
            ringbuffer::read_message<tls::tls_outbound>(data, size);

          int64_t connect_id = (int64_t)id;
          LOG_DEBUG_FMT("rpc write from enclave {}: {}", connect_id, body.size);

          write(connect_id, body.size, body.data);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, tls::tls_connect, [this](const uint8_t* data, size_t size) {
          auto [id, host, service] =
            ringbuffer::read_message<tls::tls_connect>(data, size);

          LOG_DEBUG_FMT("rpc connect request from enclave {}", id);

          if (check_enclave_side_id(id))
          {
            connect(id, host, service);
          }
          else
          {
            LOG_FAIL_FMT(
              "rpc session id is not in dedicated from-enclave range ({})", id);
          }
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, tls::tls_stop, [this](const uint8_t* data, size_t size) {
          auto [id, msg] = ringbuffer::read_message<tls::tls_stop>(data, size);

          LOG_DEBUG_FMT("rpc stop from enclave {}, {}", id, msg);
          stop(id);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, tls::tls_closed, [this](const uint8_t* data, size_t size) {
          auto [id] = ringbuffer::read_message<tls::tls_closed>(data, size);

          LOG_DEBUG_FMT("rpc closed from enclave {}", id);
          close(id);
        });
    }

  private:
    tls::ConnID get_next_id()
    {
      auto id = next_id++;
      const auto initial = id;

      if (next_id < 0)
        next_id = 1;

      while (sockets.find(id) != sockets.end())
      {
        id++;

        if (id < 0)
          id = 1;

        if (id == initial)
        {
          throw std::runtime_error(
            "Exhausted all IDs for host RPC connections");
        }
      }

      return id;
    }

    bool check_enclave_side_id(tls::ConnID id)
    {
      return id < 0;
    }

    std::string get_address(tls::ConnID id)
    {
      const auto it = sockets.find(id);
      if (it == sockets.end())
      {
        throw std::logic_error(fmt::format("No socket with id {}", id));
      }

      return fmt::format(
        "{}:{}", it->second->get_host(), it->second->get_service());
    }
  };
}
