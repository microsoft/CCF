// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "enclave/interface.h"
#include "enclave/rpc_sessions.h"
#include "node/acme_client.h"
#include "service/network_tables.h"

namespace ccf
{
  class ACMEClient : public ACME::Client
  {
  public:
    ACMEClient(
      const ACME::ClientConfig& config,
      std::shared_ptr<RPCSessions> rpc_sessions,
      std::shared_ptr<kv::Store> store,
      ringbuffer::WriterPtr to_host) :
      ACME::Client(config),
      rpc_sessions(rpc_sessions),
      store(store),
      to_host(to_host)
    {}

    virtual ~ACMEClient() {}

  protected:
    std::shared_ptr<RPCSessions> rpc_sessions;
    std::shared_ptr<kv::Store> store;
    ringbuffer::WriterPtr to_host;

    virtual void make_http_request(
      const http::URL& url,
      std::vector<uint8_t>&& req,
      std::function<
        bool(http_status status, http::HeaderMap&&, std::vector<uint8_t>&&)>
        callback) override
    {
      auto ca = std::make_shared<tls::CA>(config.ca_certs, true);
      auto ca_cert = std::make_shared<tls::Cert>(ca);
      auto client = rpc_sessions->create_client(ca_cert);

      client->connect(
        url.host,
        url.port,
        [callback](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          return callback(status, std::move(headers), std::move(data));
        });
      client->send_request(std::move(req));
    }

    virtual void on_challenge(const std::string& key_authorization) override
    {
      RINGBUFFER_WRITE_MESSAGE(
        ACMEMessage::acme_challenge_response, to_host, key_authorization);
    }

    virtual void on_certificate(const std::string& certificate) override
    {
      // Write the endorsed certificate to the service table; all nodes
      // will install it in the global hook on this table.
      auto tx = store->create_tx();
      auto service = tx.rw<Service>(Tables::SERVICE);
      auto service_info = service->get();
      service_info->tls_cert = crypto::Pem(certificate);
      service->put(service_info.value());
      tx.commit();

      RINGBUFFER_WRITE_MESSAGE(
        ACMEMessage::acme_challenge_server_stop, to_host);
    }
  };
}
