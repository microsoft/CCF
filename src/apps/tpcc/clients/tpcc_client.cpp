// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../tpcc_serializer.h"
#include "perf_client.h"

using namespace std;
using namespace nlohmann;

struct TpccClientOptions : public client::PerfOptions
{
  TpccClientOptions(CLI::App& app, const std::string& default_pid_file) :
    client::PerfOptions("Tpcc_ClientCpp", default_pid_file, app)
  {}
};

using Base = client::PerfBase<TpccClientOptions>;

class TpccClient : public Base
{
private:
  enum class TransactionTypes : uint8_t
  {
    stock_level = 0,
    order_status,
    delivery,
    payment,
    new_order,

    NumberTransactions
  };

  const char* OPERATION_C_STR[5]{
    "stock_level", "order_status", "delivery", "payment", "new_order"};

  std::optional<RpcTlsClient::Response> send_creation_transactions() override
  {
    auto connection = get_connection();
    tpcc::DbCreation db;
    db.new_orders_per_district = 1000;
    db.seed = 42;
    const auto body = db.serialize();
    const auto response =
      connection->call("tpcc_create", CBuffer{body.data(), body.size()});
    check_response(response);

    return response;
  }

  void prepare_transactions() override
  {
    // Reserve space for transfer transactions
    prepared_txs.resize(options.num_transactions);

    for (decltype(options.num_transactions) i = 0; i < options.num_transactions;
         i++)
    {
      uint8_t operation;
      uint8_t x = rand_range(100);

      std::vector<uint8_t> serialized_body;

      if (x < 4)
      {
        tpcc::StockLevel sl;
        sl.warehouse_id = 1;
        sl.district_id = 1;
        sl.threshold = 1000;
        sl.seed = rand_range<int32_t>();
        serialized_body = sl.serialize();
        operation = (uint8_t)TransactionTypes::stock_level;
      }
      else if (x < 8)
      {
        tpcc::TxInfo info;
        info.seed = rand_range<int32_t>();
        serialized_body = info.serialize();
        operation = (uint8_t)TransactionTypes::delivery;
      }
      else if (x < 12)
      {
        tpcc::TxInfo info;
        info.seed = rand_range<int32_t>();
        serialized_body = info.serialize();
        operation = (uint8_t)TransactionTypes::order_status;
      }
      else if (x < (12 + 43))
      {
        tpcc::TxInfo info;
        info.seed = rand_range<int32_t>();
        serialized_body = info.serialize();
        operation = (uint8_t)TransactionTypes::payment;
      }
      else
      {
        tpcc::TxInfo info;
        info.seed = rand_range<int32_t>();
        serialized_body = info.serialize();
        operation = (uint8_t)TransactionTypes::new_order;
      }
      add_prepared_tx(
        OPERATION_C_STR[operation],
        CBuffer{serialized_body.data(), serialized_body.size()},
        true, // expect commit
        i);
    }
  }

  bool check_response(const RpcTlsClient::Response& r) override
  {
    if (!http::status_success(r.status))
    {
      const std::string error_msg(r.body.begin(), r.body.end());
      throw logic_error(error_msg);
      return false;
    }

    return true;
  }

  void pre_creation_hook() override
  {
    // empty
  }

  void post_creation_hook() override
  {
    // empty
  }

  void post_timing_body_hook() override
  {
    // empty
  }

  void verify_params(const nlohmann::json& expected) override
  {
    Base::verify_params(expected);
  }

  void verify_initial_state(const nlohmann::json& expected) override
  {
    // empty
  }

  void verify_final_state(const nlohmann::json& expected) override
  {
    // empty
  }

public:
  TpccClient(const TpccClientOptions& o) : Base(o) {}
};

int main(int argc, char** argv)
{
  CLI::App cli_app{"Tpcc Client"};
  TpccClientOptions options(cli_app, argv[0]);
  CLI11_PARSE(cli_app, argc, argv);

  TpccClient client(options);
  client.run();

  return 0;
}
