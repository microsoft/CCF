// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "ITimer.h"
#include "Message.h"
#include "Replica.h"
#include "ds/logger.h"
#include "network.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unordered_map>
#include <zmq.hpp>

class ZMQTCPNetwork : public INetwork
{
public:
  ZMQTCPNetwork() : _ctx(1), _socket(_ctx, ZMQ_PULL) {}
  virtual ~ZMQTCPNetwork() = default;

  virtual bool Initialize(in_port_t port)
  {
    std::string conn_string("tcp://*:");
    conn_string.append(std::to_string(htons(port)));
    LOG_INFO << "Binding to " << conn_string << std::endl;

    _socket.bind(conn_string.c_str());
    return true;
  }

  virtual int Send(Message* message, IPrincipal& principal)
  {
    struct sockaddr* to = (struct sockaddr*)principal.address();

    uint64_t conn_hash = 0;
    conn_hash = ((sockaddr_in*)to)->sin_addr.s_addr;
    conn_hash = conn_hash << 32;
    conn_hash += ((sockaddr_in*)to)->sin_port;

    ConnectionState* conn_state = nullptr;
    auto it = _connections.find(conn_hash);
    if (it == _connections.end())
    {
      auto state = std::make_unique<ConnectionState>();
      state->conn_string = std::string("tcp://");
      state->conn_string.append(inet_ntoa(((sockaddr_in*)to)->sin_addr));
      state->conn_string.append(":");
      state->conn_string.append(
        std::to_string(htons(((sockaddr_in*)to)->sin_port)));

      LOG_INFO << "Connecting to " << state->conn_string << std::endl;
      state->socket.connect(state->conn_string.c_str());

      conn_state = state.get();
      _connections.insert({conn_hash, std::move(state)});
    }
    else
    {
      conn_state = it->second.get();
    }

    Auth_type atype;
    int src_offset, len, dst_offset;
    message->get_mac_parameters(atype, src_offset, len, dst_offset);
    node->gen_mac(
      principal.pid(),
      atype,
      message->contents() + src_offset,
      len,
      message->contents() + dst_offset);

    zmq::message_t msg(message->contents(), message->size());
    bool result = conn_state->socket.send(msg, ZMQ_NOBLOCK);
    if (!result)
    {
      int err = errno;
      if (err != EAGAIN)
      {
        conn_state->socket.disconnect(conn_state->conn_string);
        // TODO: do smart reconnect
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

      if (Replica::pre_verify(m))
      {
        return m;
      }
    }

    while (true)
    {
      ITimer::handle_timeouts();
      if (!_socket.recv(&_pending_msg, ZMQ_NOBLOCK))
      {
        int err = errno;
        if (err == EAGAIN)
        {
          continue;
        }
        LOG_FATAL << "failed to receive message, error:" << err << std::endl;
      }

      CopyFromPendingMessage(m->contents());
      if (Replica::pre_verify(m))
      {
        return m;
      }
    }
  }

  virtual bool has_messages(long to)
  {
    assert(to == 0);

    if (_is_msg_pending)
    {
      return true;
    }

    if (!_socket.recv(&_pending_msg, ZMQ_NOBLOCK))
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
  void CopyFromPendingMessage(void* buf)
  {
    memcpy(buf, _pending_msg.data(), _pending_msg.size());
    _is_msg_pending = false;
    _pending_msg.~message_t();
    new (&_pending_msg) zmq::message_t();
  }

  struct ConnectionState
  {
    ConnectionState() : ctx(1), socket(ctx, ZMQ_PUSH) {}

    zmq::context_t ctx;
    zmq::socket_t socket;
    std::string conn_string;
  };

private:
  zmq::context_t _ctx;
  zmq::socket_t _socket;
  zmq::message_t _pending_msg;
  bool _is_msg_pending = false;

  std::unordered_map<uint64_t, std::unique_ptr<ConnectionState>> _connections;
};

std::unique_ptr<INetwork> Create_ZMQ_TCP_Network()
{
  return std::make_unique<ZMQTCPNetwork>();
}
