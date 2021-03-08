// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdint.h>
#include <exception>
#include <set>

#include "tpcc_tables.h"

namespace tpcc
{
  class SetupDb
  {
  private:
    ccf::EndpointContext& args;
    uint32_t num_wh;
    uint32_t num_items;
    bool already_run;

  public:
    SetupDb(ccf::EndpointContext& args_, uint32_t num_wh_, uint32_t num_items_) :
      args(args_), num_wh(num_wh_), num_items(num_items_), already_run(false)
    {}

    template<size_t T>
    void create_random_string(std::array<char, T>& str, uint32_t length)
    {
      for (uint32_t i =0; i < length-1; ++i)
      {
        str[i] = 97 + rand() % 26; // lower case letters
      }
      str[length - 1] = '\0';
    }

    std::unordered_set<uint32_t> select_unique_ids(uint32_t num_items, uint32_t num_unique)
    {
      std::unordered_set<uint32_t> r;
      for (uint32_t i = 0; i < num_items; ++i)
      {
        r.insert(i);
      }

      while (r.size() > num_unique)
      {
        r.erase(r.begin());
      }
      return r;
    }

    template<size_t T>
    void set_original(std::array<char, T>& s)
    {
      int position = rand() % (T - 8);
      memcpy(s.data() + position, "ORIGINAL", 8);
    }

    Stock generate_stock(uint32_t item_id, uint32_t wh_id, bool is_original)
    {
      Stock s;
      assert(1 >= item_id && item_id <= num_items);
      s.s_i_id = item_id;
      s.s_w_id = wh_id;
      s.s_quantity =
        (rand() % (Stock::MAX_QUANTITY - Stock::MIN_QUANTITY)) +
        Stock::MIN_QUANTITY;
      s.s_ytd = 0;
      s.s_order_cnt = 0;
      s.s_remote_cnt = 0;
      for (int i = 0; i < District::NUM_PER_WAREHOUSE; ++i)
      {
        create_random_string(s.s_dist[i], sizeof(s.s_dist[i]));
      }

      if (is_original)
      {
        set_original(s.s_data);
      }
      else
      {
        create_random_string(
          s.s_data,
          rand() % (Stock::MAX_DATA - Stock::MIN_DATA) + Stock::MIN_DATA);
      }
      return s;
    }

    void make_stock(uint32_t wh_id)
    {
      // Select 10% of the stock to be marked "original"
      std::unordered_set<uint32_t> selected_rows =
        select_unique_ids(num_items, num_items/10);

      for (uint32_t i = 1; i <= num_items; ++i)
      {
        bool is_original = selected_rows.find(i) != selected_rows.end();
        Stock s = generate_stock(i, wh_id, is_original);
        // TODO: add stock
        //tables->insertStock(s);
        auto stocks = args.tx.rw(tpcc::TpccTables::stocks);
        stocks->put(s.get_key(), s);
      }
    }

    void run()
    {
      if (already_run)
      {
        throw std::logic_error("Can only create the database 1 time");
      }
      already_run = true;

      for(uint32_t i =0; i < num_wh; ++i)
      {
        make_stock(i);
        //makeWarehouseWithoutStock(i);
      }
    }
  };
}