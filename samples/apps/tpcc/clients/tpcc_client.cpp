// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "perf_client.h"
#include <ctime>

using namespace std;
using namespace nlohmann;

using Base = client::PerfBase;

class TpccClient : public Base
{
private:
  enum class TransactionTypes : uint8_t
  {
    NewOrder = 0,

    NumberTransactions
  };

  uint64_t num_warehouses = 5;

  void send_creation_transactions(
    const std::shared_ptr<RpcTlsClient>& connection) override
  {
    // Hook method to set up initial state of the KV store
    // TODO: send RPCs to create items, warehouses, etc.
  }

  void prepare_transactions() override
  {
    // Reserve space for transactions
    prepared_txs.resize(num_transactions);

    for (decltype(num_transactions) i = 0; i < num_transactions; i++)
    {
      // For now we just do 'NewOrder' transactions, in future we should
      // select each transaction using random sampling.

      json params = generate_new_order_params();

      add_prepared_tx("TPCC_new_order", params, true, i);
    }

  }

  json generate_new_order_params()
  {

    // TODO: refactor constants

    json params;

    // Warehouse ID
    uint64_t w_id = rand_range(num_warehouses) + 1;
    params["w_id"] = w_id;

    // District ID: Rand[1, 10] from home warehouse
    params["d_id"] = rand_range(1, 11);

    // Customer ID: NURand[1023, 1, 3000] from district number
    params["c_id"] = nu_rand(1023, 1, 3000);

    // Entry Date: current date time
    std::time_t t = std::time(0);
    params["o_entry_d"] = ctime(&t);

    // Number of items: Rand[5, 15]
    uint64_t ol_cnt = rand_range(5, 16);
    
    params["i_ids"] = {};
    params["i_w_ids"] = {};
    params["i_qtys"] = {};

    // 1% of transactions will rollback
    bool rollback = rand_range(0, 100) == 0;

    // Generate Items
    for (size_t i = 1; i <= ol_cnt; i++)
    {
      // Item Id: NURand[8191, 1, 100000]
      uint64_t i_id = nu_rand(8191, 1, 100000);

      if (rollback && i == ol_cnt)
      {
        i_id = 100001; // Unused value
      }

      params["i_ids"].push_back(i_id);

      // Supplying Warehouse: 99% home, 1% remote
      uint64_t o_supply_w_id = w_id;
      if (rand_range(0, 100) == 0)
      {
        do
        {
          o_supply_w_id = rand_range(num_warehouses) + 1;
        }
        while (o_supply_w_id == w_id);
      }

      params["i_w_ids"].push_back(o_supply_w_id);

      // Quantity: Rand[1, 10]
      params["i_qtys"].push_back(rand_range(1, 11));
    }

    return params;
  }

  /*
    Non-Uniform Random number, NURand[A, x, y], as per TPCC 2.1.6
  */
  template <typename T>
  T nu_rand(T a, T x, T y)
  {
    T c = 0;
    // TODO: implement setting C correctly
    return (((rand_range(0, a) | rand_range(x, y)) + c) % (y - x + 1)) + x;
  }

public:
  TpccClient() : Base("Tpcc_ClientCpp") {}

  void setup_parser(CLI::App& app) override
  {
    Base::setup_parser(app);

    app.add_option("--num_warehouses", num_warehouses);
  }

};

int main(int argc, char** argv)
{
  TpccClient client;
  CLI::App cli_app{"TPCC Client"};
  client.setup_parser(cli_app);
  CLI11_PARSE(cli_app, argc, argv);

  client.run();

  return 0;
}