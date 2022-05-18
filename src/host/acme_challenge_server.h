// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"
#include "ccf/http_status.h"
#include "ccf/json_handler.h"
#include "ds/ring_buffer_types.h"
#include "enclave/interface.h"
#include "host/socket.h"
#include "http/http_builder.h"
#include "http/http_endpoint.h"
#include "http/http_parser.h"
#include "tcp.h"

#include <cstddef>
#include <fmt/format.h>
#include <memory>
#include <stdexcept>
#include <uv.h>

class ACMEConnectionTracker
{
public:
  virtual void add(asynchost::TCP& peer) = 0;
};

class ACMEServerBehaviour : public asynchost::SocketBehaviour<asynchost::TCP>
{
protected:
  class ClientBehaviour : public asynchost::SocketBehaviour<asynchost::TCP>
  {
  public:
    ClientBehaviour(
      asynchost::TCP socket,
      std::mutex& lock,
      const std::map<std::string, std::string>& prepared_responses,
      ringbuffer::WriterPtr to_enclave) :
      asynchost::SocketBehaviour<asynchost::TCP>("", ""),
      parser(sp),
      socket(socket),
      lock(lock),
      prepared_responses(prepared_responses),
      to_enclave(to_enclave)
    {}

    virtual ~ClientBehaviour() {}

    void reply(http::Response& r, const std::string& body)
    {
      if (!socket.is_null())
      {
        std::vector<uint8_t> vody(body.begin(), body.end());
        r.set_body(vody.data(), vody.size());
        auto bytes = r.build_response();
        socket->write(bytes.size(), bytes.data());
      }
    }

    virtual void on_read(size_t len, uint8_t*& incoming, sockaddr sa) override
    {
      std::string body((char*)incoming, len);

      try
      {
        parser.execute(incoming, len);
        while (!sp.received.empty())
        {
          auto req = sp.received.front();
          sp.received.pop();

          // We serve only
          // http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN>
          if (req.url.find("/.well-known/acme-challenge/") != 0)
          {
            LOG_INFO_FMT("ACME: invalid url={} body={}", req.url, body);
            http::Response r(HTTP_STATUS_NOT_FOUND);
            reply(r, "Not found");
          }
          else
          {
            auto token = req.url.substr(req.url.rfind('/') + 1);

            if (token.empty())
            {
              throw std::runtime_error("Missing ACME token");
            }

            {
              std::unique_lock<std::mutex> guard(lock);

              auto tit = prepared_responses.find(token);
              if (tit == prepared_responses.end())
              {
                LOG_DEBUG_FMT(
                  "ACME: token response for token '{}' not found", token);
                http::Response r(HTTP_STATUS_NOT_FOUND);
                reply(
                  r, fmt::format("No response for token '{}' found", token));
              }
              else
              {
                auto rbody = fmt::format("{}.{}", tit->first, tit->second);
                LOG_DEBUG_FMT(
                  "ACME: challenge response to token '{}': {}", token, rbody);
                http::Response r(HTTP_STATUS_OK);
                r.set_header("Content-Type", "application/octet-stream");
                reply(r, rbody);

                RINGBUFFER_WRITE_MESSAGE(
                  ACMEMessage::acme_challenge_complete, to_enclave, token);
              }
            }
          }
        }
      }
      catch (const std::exception& ex)
      {
        http::Response r(HTTP_STATUS_BAD_REQUEST);
        reply(r, "Bad request");
      }
    }

  protected:
    http::SimpleRequestProcessor sp;
    http::RequestParser parser;
    asynchost::TCP socket;

    std::mutex& lock;
    const std::map<std::string, std::string>& prepared_responses;
    ringbuffer::WriterPtr to_enclave;
  };

public:
  ACMEServerBehaviour(
    ACMEConnectionTracker& tracker,
    std::mutex& lock,
    const std::map<std::string, std::string>& prepared_responses,
    ringbuffer::WriterPtr to_enclave) :
    asynchost::SocketBehaviour<asynchost::TCP>("", ""),
    tracker(tracker),
    lock(lock),
    prepared_responses(prepared_responses),
    to_enclave(to_enclave)
  {}

  void on_listening(
    const std::string& host, const std::string& service) override
  {
    LOG_DEBUG_FMT("Listening for ACME connections on {}:{}", host, service);
  }

  void on_accept(asynchost::TCP& peer) override
  {
    LOG_DEBUG_FMT(
      "Accepted new incoming ACME connection from {}", peer->get_peer_name());
    peer->set_behaviour(std::make_unique<ClientBehaviour>(
      peer, lock, prepared_responses, to_enclave));
    tracker.add(peer);
  }

  virtual void on_read(size_t len, uint8_t*& incoming, sockaddr sa) override
  {
    LOG_TRACE_FMT("ACME: received {} bytes", len);
  }

  virtual void on_resolve_failed() override
  {
    LOG_TRACE_FMT("ACME: on_resolve_failed");
  }

  virtual void on_listen_failed() override
  {
    LOG_TRACE_FMT("ACME: on_listen_failed");
  }

  virtual void on_bind_failed() override
  {
    LOG_TRACE_FMT("ACME: on_bind_failed");
  }

  virtual void on_connect() override
  {
    LOG_TRACE_FMT("ACME: on_connect");
  }

  virtual void on_connect_failed() override
  {
    LOG_TRACE_FMT("ACME: on_connect_failed");
  }

  virtual void on_disconnect() override
  {
    LOG_TRACE_FMT("ACME: on_disconnect");
  }

  ACMEConnectionTracker& tracker;
  std::mutex& lock;
  const std::map<std::string, std::string>& prepared_responses;
  ringbuffer::WriterPtr to_enclave;
};

class ACMEChallengeServer : public ACMEConnectionTracker
{
public:
  ACMEChallengeServer(
    const std::string& host,
    messaging::Dispatcher<ringbuffer::Message>& disp,
    ringbuffer::AbstractWriterFactory& writer_factory) :
    to_enclave(writer_factory.create_writer_to_inside())
  {
    LOG_INFO_FMT("Starting ACME challenge server");
    listener->set_behaviour(std::make_unique<ACMEServerBehaviour>(
      *this, lock, prepared_responses, to_enclave));
    listener->listen(host, "80"); // Port fixed, not optional.

    DISPATCHER_SET_MESSAGE_HANDLER(
      disp,
      ACMEMessage::acme_challenge_response,
      [this](const uint8_t* data, size_t size) {
        try
        {
          auto [response] =
            ringbuffer::read_message<ACMEMessage::acme_challenge_response>(
              data, size);

          auto dotidx = response.find(".");
          auto token = response.substr(0, dotidx);
          auto key_authentication = response.substr(dotidx + 1);

          LOG_DEBUG_FMT(
            "ACME: challenge server received response for token '{}' ({})",
            token,
            key_authentication);

          {
            std::unique_lock<std::mutex> guard(lock);
            prepared_responses.emplace(token, key_authentication);
          }

          RINGBUFFER_WRITE_MESSAGE(
            ACMEMessage::acme_challenge_response_ack, to_enclave, token);
        }
        catch (const std::exception& ex)
        {
          LOG_FAIL_FMT(
            "ACME: acme_challenge_response message handler failed: {}",
            ex.what());
        }
      });
  }

  virtual ~ACMEChallengeServer() {}

  virtual void add(asynchost::TCP& peer) override
  {
    sockets.emplace(sockets.size(), peer);
  }

protected:
  asynchost::TCP listener;
  std::unordered_map<size_t, asynchost::TCP> sockets;
  std::mutex lock;
  std::map<std::string, std::string> prepared_responses;
  ringbuffer::WriterPtr to_enclave;
};