// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "libbyz/libbyz.h"
#include "libbyz/pbft_assert.h"
#include "pbft/pbft_deps.h"

namespace pbft
{
  class AbstractPbftConfig
  {
  public:
    static char* service_mem;
    virtual ~AbstractPbftConfig() = default;
    virtual void set_service_mem(char* sm) = 0;
    virtual ExecCommand get_exec_command() = 0;
    virtual size_t message_size() = 0;
    virtual void fill_request(
      uint8_t* buffer,
      size_t total_req_size,
      const std::vector<uint8_t>& data,
      size_t jsonrpc_id) = 0;
  };

  char* AbstractPbftConfig::service_mem = 0;

  class PbftConfigCcf : public AbstractPbftConfig
  {
  public:
    ~PbftConfigCcf() = default;

    void set_service_mem(char* sm) override
    {
      service_mem = sm;
    }

    ExecCommand get_exec_command() override
    {
      return exec_command;
    }

    size_t message_size() override
    {
      return sizeof(ccf_req);
    }

    void fill_request(
      uint8_t* buffer,
      size_t total_req_size,
      const std::vector<uint8_t>& data,
      size_t jsonrpc_id) override
    {
      auto request = new (buffer) ccf_req;
      request->jsonrpc_id = jsonrpc_id;
      auto array_size = request->get_array_size(total_req_size);

      for (size_t j = 0; j < array_size; j++)
      {
        memcpy(&request->get_counter_array()[j], &data[j], sizeof(uint8_t));
      }
    }

  private:
    struct ccf_req
    {
      size_t jsonrpc_id;

      uint8_t* get_counter_array()
      {
        return (uint8_t*)((uintptr_t)this + sizeof(ccf_req));
      }

      size_t get_array_size(size_t total_size)
      {
        if (total_size < sizeof(ccf_req))
        {
          return 0;
        }
        return (total_size - sizeof(ccf_req)) / sizeof(uint8_t);
      }
    };

    // TODO (#pbft) this is an example exec_command to ge the integration
    // started. For now it just takes as input (inb) the json-rpc id and the
    // json-rpc command. This will be refactored and completed in the upcoming
    // pull requests
    ExecCommand exec_command = [](
                                 Byz_req* inb,
                                 Byz_rep* outb,
                                 _Byz_buffer* non_det,
                                 int client,
                                 bool ro,
                                 Seqno total_requests_executed) {
      Long& counter = *(Long*)service_mem;

      Byz_modify(&counter, sizeof(counter));
      counter++;

      if (total_requests_executed != counter)
      {
        LOG_FATAL_FMT(
          "total requests executed: {} not equal to exec command counter: {}",
          total_requests_executed,
          counter);
        throw std::logic_error(
          "Total requests executed not equal to exec command counter");
      }

      if (total_requests_executed % 100 == 0)
      {
        LOG_INFO_FMT("total requests executed {}", total_requests_executed);
      }

      LOG_INFO_FMT("request inb size: {}", inb->size);

      auto request = new (inb->contents) ccf_req;

      LOG_INFO_FMT("received request with jsonrpc id: {}", request->jsonrpc_id);

      auto size_of_array = request->get_array_size(inb->size);
      std::vector<uint8_t> data(size_of_array);
      for (size_t j = 0; j < size_of_array; j++)
      {
        memcpy(&data[j], &request->get_counter_array()[j], sizeof(uint8_t));
      }

      Byz_modify(outb->contents, 8);
      bzero(outb->contents, 8);
      outb->size = 8;
      return 0;
    };
  };
}