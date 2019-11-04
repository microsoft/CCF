// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once
#include "../network_impl.h"
#include "ITimer.h"
#include "Message.h"
#include "Node.h"
#include "assert.h"
#include "ds/logger.h"

#include <unordered_map>

class MockNetwork : public INetwork
{
public:
  virtual ~MockNetwork() = default;

  virtual bool Initialize(in_port_t port)
  {
    std::string conn_string("");
    conn_string.append(std::to_string(htons(port)));
    LOG_INFO << "Test network binding to " << conn_string << std::endl;
    return true;
  }

  virtual int Send(Message* message, IPrincipal& principal)
  {
    sockaddr_in* to = (sockaddr_in*)principal.address();

    uint64_t conn_hash = 0;
    conn_hash = to->sin_addr.s_addr;
    conn_hash = conn_hash << 32;
    conn_hash += to->sin_port;

    ConnectionState* conn_state = nullptr;
    auto it = _connections.find(conn_hash);
    if (it == _connections.end())
    {
      auto state = std::make_unique<ConnectionState>();
      state->conn_string = std::string("");
      state->conn_string.append(std::to_string(to->sin_addr.s_addr));
      state->conn_string.append(":");
      state->conn_string.append(std::to_string(to->sin_port));

      LOG_INFO << "Connecting to " << state->conn_string << std::endl;

      conn_state = state.get();
      _connections.insert({conn_hash, std::move(state)});
    }
    else
    {
      conn_state = it->second.get();
    }

    uint8_t* tmp_buf = (uint8_t*)message->contents();
    std::vector<uint8_t> msg = {tmp_buf, tmp_buf + message->size()};
    // socket send message
    bool result = conn_state->socket.send(msg);
    if (!result)
    {
      int err = errno;
      if (err != EAGAIN)
      {
        LOG_INFO << "failed to send message, error:" << err << std::endl;
        _connections.erase(it);
      }
    }

    return message->size();
  }

  virtual Message* GetNextMessage()
  {
    Message* m = new Message(Max_message_size);
    if (_is_msg_pending)
    {
      CopyFromPendingMessage(m->contents());
      return m;
    }

    while (true)
    {
      ITimer::handle_timeouts();
      if (!_socket.recv())
      {
        int err = errno;
        if (err == EAGAIN)
        {
          continue;
        }
        LOG_FATAL << "failed to receive message, error:" << err << std::endl;
      }

      CopyFromPendingMessage(m->contents());
      return m;
    }
  }

  virtual bool has_messages(long to)
  {
    assert(to == 0);

    if (_is_msg_pending)
    {
      return true;
    }

    if (!_socket.recv())
    {
      int err = errno;
      if (err == EAGAIN)
      {
        return false;
      }
      LOG_FATAL << "failed to receive message, error:" << err << std::endl;
    }
    _is_msg_pending = true;
    return true;
  }

private:
  struct Socket
  {
    static std::vector<std::vector<uint8_t>> messages;
    int ctx;

    Socket(int ctx_) : ctx(ctx_) {}

    bool send(std::vector<uint8_t> message)
    {
      messages.emplace_back(message);
      return true;
    }

    bool recv()
    {
      if (messages.size() == 0)
        return false;
      _pending_msg = messages.back();
      messages.pop_back();
      return true;
    }
  };

  void CopyFromPendingMessage(void* buf)
  {
    memcpy(buf, _pending_msg.data(), _pending_msg.size());
    _is_msg_pending = false;
    _pending_msg.clear();
  }

  struct ConnectionState
  {
    ConnectionState() : ctx(1), socket(ctx) {}

    int ctx;
    Socket socket;
    std::string conn_string;
  };

private:
  static Socket _socket;
  static std::vector<uint8_t> _pending_msg;
  bool _is_msg_pending = false;

  std::unordered_map<uint64_t, std::unique_ptr<ConnectionState>> _connections;
};

INetwork* Create_Mock_Network();
