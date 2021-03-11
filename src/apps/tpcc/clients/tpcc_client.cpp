// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../smallbank_serializer.h"
#include "perf_client.h"

using namespace std;
using namespace nlohmann;

struct SmallBankClientOptions : public client::PerfOptions
{
  size_t warehouses = 10;

  SmallBankClientOptions(CLI::App& app, const std::string& default_pid_file) :
    client::PerfOptions("Tpcc_ClientCpp", default_pid_file, app)
  {
    app.add_option("--warehouses", warehouses)->capture_default_str();
  }
};

using Base = client::PerfBase<SmallBankClientOptions>;

class SmallBankClient : public Base
{
private:
  enum class TransactionTypes : uint8_t
  {
    create = 0,
    stock_level,
    order_status,

    NumberTransactions
  };

  const char* OPERATION_C_STR[5]{"tpcc_create", "stock_level", "order_status"};

  std::optional<RpcTlsClient::Response> send_creation_transactions() override
  {
    auto connection = get_connection();
    LOG_INFO_FMT("calling tpcc db");
    tpcc::TpccDbCreation db;
    db.num_wh = 10;
    db.num_items = 1000;
    db.customers_per_district = 1000;
    db.districts_per_warehouse = 10;
    db.new_orders_per_district = 1000;
    const auto body = db.serialize();
    const auto response = connection->call(
      "tpcc_create", CBuffer{body.data(), body.size()});
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
      uint8_t operation =
        rand_range((uint8_t)TransactionTypes::NumberTransactions);

      std::vector<uint8_t> serialized_body;

      switch ((TransactionTypes)operation)
      {
        case TransactionTypes::create:
        {
          tpcc::TpccDbCreation db;
          db.num_wh = 10;
          db.num_items = 1000;
          db.customers_per_district = 1000;
          db.districts_per_warehouse = 10;
          db.new_orders_per_district = 1000;
          serialized_body = db.serialize();
        }
        break;

        case TransactionTypes::stock_level:
        {
          tpcc::TpccStockLevel sl;
          sl.warehouse_id = 1;
          sl.district_id = 1;
          sl.threshold = 1000;
          serialized_body = sl.serialize();
        }
        break;

        case TransactionTypes::order_status:
        {
          tpcc::TpccOrderStatus os;
          os.warehouse_id = 1;
          os.district_id = 1;
          os.threshold = 1000;
          serialized_body = os.serialize();
        }
        break;

        default:
          throw logic_error("Unknown operation");
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
      if (
        error_msg.find("Not enough money in savings account") == string::npos &&
        error_msg.find("Account already exists in accounts table") ==
          string::npos)
      {
        throw logic_error(error_msg);
        return false;
      }
    }

    return true;
  }

  void pre_creation_hook() override
  {
    LOG_DEBUG_FMT("Creating {} warehouses", options.warehouses);
  }

  void post_creation_hook() override
  {
    LOG_TRACE_FMT("Initial accounts:");
  }

  void post_timing_body_hook() override
  {
    LOG_TRACE_FMT("Final accounts:");
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
  SmallBankClient(const SmallBankClientOptions& o) : Base(o) {}
};

int main(int argc, char** argv)
{
  CLI::App cli_app{"Small Bank Client"};
  SmallBankClientOptions options(cli_app, argv[0]);
  CLI11_PARSE(cli_app, argc, argv);

  SmallBankClient client(options);
  client.run();

  return 0;
}
