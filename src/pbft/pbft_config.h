// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "libbyz/libbyz.h"
#include "libbyz/pbft_assert.h"
#include "pbft/pbft_deps.h"

namespace pbft
{
  static char* service_mem = 0;

  class PbftConfig
  {
  public:
    virtual ~PbftConfig() = default;
    virtual ExecCommand get_exec_command() = 0;
    virtual size_t message_size() = 0;
    virtual void fill_request(
      uint8_t* buffer,
      const size_t& total_req_size,
      const std::vector<uint8_t>& data,
      const size_t& version) = 0;
  };

  class PbftConfigCCF : public PbftConfig
  {
  public:
    ~PbftConfigCCF() = default;

    size_t message_size() override
    {
      return sizeof(ccf_req);
    }

    void fill_request(
      uint8_t* buffer,
      const size_t& total_req_size,
      const std::vector<uint8_t>& data,
      const size_t& version) override
    {
      auto request = new (buffer) ccf_req;
      request->version = version;
      auto array_size = request->get_array_size(total_req_size);

      for (size_t j = 0; j < array_size; j++)
      {
        memcpy(&request->get_counter_array()[j], &data[j], sizeof(uint8_t));
      }
    }

    struct ccf_req
    {
      size_t version;

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

  private:
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
        LOG_FATAL << "total requests executed: " << total_requests_executed
                  << " not equal to exec command counter: " << counter << "\n";
        throw std::logic_error(
          "Total requests executed not equal to exec command counter");
      }

      if (total_requests_executed % 100 == 0)
      {
        LOG_INFO << "total requests executed " << total_requests_executed
                 << "\n";
      }

      LOG_INFO << "request inb size: " << inb->size << std::endl;

      auto request = new (inb->contents) ccf_req;

      LOG_INFO << "received request with version: " << request->version
               << std::endl;

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

    ExecCommand get_exec_command() override
    {
      return exec_command;
    }
  };
}