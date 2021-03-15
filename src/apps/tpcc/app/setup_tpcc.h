// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tpcc_tables.h"
#include "tpcc_common.h"

#include <exception>
#include <set>
#include <stdint.h>

namespace tpcc
{
  class SetupDb
  {
  private:
    ccf::EndpointContext& args;
    bool already_run;
    int32_t new_orders_per_district;
    std::mt19937 rand_generator;

    float random_float(float min, float max)
    {
      return tpcc::random_float(min, max, rand_generator);
    }

    uint32_t random_int(uint32_t min, uint32_t max)
    {
      return tpcc::random_int(min, max, rand_generator);
    }

    int32_t random_int_excluding(int lower, int upper, int excluding)
    {
      return tpcc::random_int_excluding(lower, upper, excluding, rand_generator);
    }

  public:
    SetupDb(
      ccf::EndpointContext& args_,
      int32_t new_orders_per_district_,
      uint32_t seed) :
      args(args_),
      already_run(false),
      new_orders_per_district(new_orders_per_district_)
    {
      rand_generator.seed(seed);
    }

    template <size_t T>
    void create_random_string(
      std::array<char, T>& str, uint32_t min, uint32_t max)
    {
      assert(max >= min);
      uint32_t rand;
      if (min == max)
      {
        rand = min;
      }
      else
      {
        rand = random_int(min, max);
      }

      create_random_string(str, rand);
    }

    template <size_t T>
    void create_random_string(std::array<char, T>& str, uint32_t length)
    {
      for (uint32_t i = 0; i < length - 1; ++i)
      {
        str[i] = 97 + random_int(0,26); // lower case letters
      }
      str[length - 1] = '\0';
    }

    template <size_t T>
    void create_random_int(std::array<char, T>& str, uint32_t length)
    {
      for (uint32_t i = 0; i < length - 1; ++i)
      {
        str[i] = 48 + random_int(0,10); // lower case letters
      }
      str[length - 1] = '\0';
    }

    std::unordered_set<uint32_t> select_unique_ids(
      uint32_t num_items, uint32_t num_unique)
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

    template <size_t T>
    void set_original(std::array<char, T>& s)
    {
      int position = random_int(0, T - 8);
      memcpy(s.data() + position, "ORIGINAL", 8);
    }

    Stock generate_stock(uint32_t item_id, uint32_t wh_id, bool is_original)
    {
      Stock s;
      s.s_i_id = item_id;
      s.s_w_id = wh_id;
      s.s_quantity = random_int(Stock::MIN_QUANTITY, Stock::MAX_QUANTITY);
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
          random_int(Stock::MIN_DATA, Stock::MAX_DATA));
      }
      return s;
    }

    void make_stock(uint32_t wh_id)
    {
      // Select 10% of the stock to be marked "original"
      std::unordered_set<uint32_t> selected_rows =
        select_unique_ids(num_items, num_items / 10);

      for (uint32_t i = 1; i <= num_items; ++i)
      {
        bool is_original = selected_rows.find(i) != selected_rows.end();
        Stock s = generate_stock(i, wh_id, is_original);
        auto stocks = args.tx.rw(tpcc::TpccTables::stocks);
        stocks->put(s.get_key(), s);
      }
    }

    void generate_warehouse(int32_t id, Warehouse* warehouse)
    {
      warehouse->w_id = id;
      warehouse->w_tax = random_float(Warehouse::MIN_TAX, Warehouse::MAX_TAX);
      warehouse->w_ytd = Warehouse::INITIAL_YTD;
      create_random_string(
        warehouse->w_name,
        random_int(Warehouse::MIN_NAME, Warehouse::MAX_NAME));
      create_random_string(
        warehouse->w_street_1,
        random_int(Address::MIN_STREET, Address::MAX_STREET));
      create_random_string(
        warehouse->w_street_2,
        random_int(Address::MIN_STREET, Address::MAX_STREET));
      create_random_string(
        warehouse->w_city,
        random_int(Address::MIN_CITY, Address::MAX_CITY));
      create_random_string(
        warehouse->w_state,
        random_int(Address::MIN_CITY, Address::MAX_CITY));
      create_random_string(warehouse->w_zip, Address::ZIP);
    }

    void generate_district(int32_t id, int32_t w_id, District* district)
    {
      district->d_id = id;
      district->d_w_id = w_id;
      district->d_tax = random_float(District::MIN_TAX, District::MAX_TAX);
      district->d_ytd = District::INITIAL_YTD;
      district->d_next_o_id = customers_per_district + 1;
      create_random_string(
        district->d_name, District::MIN_NAME, District::MAX_NAME);
      create_random_string(
        district->d_street_1, Address::MIN_STREET, Address::MAX_STREET);
      create_random_string(
        district->d_street_2, Address::MIN_STREET, Address::MAX_STREET);
      create_random_string(
        district->d_city, Address::MIN_CITY, Address::MAX_CITY);
      create_random_string(district->d_state, Address::STATE, Address::STATE);
      create_random_string(district->d_zip, Address::ZIP);
    }

    void generate_customer(
      int32_t id,
      int32_t d_id,
      int32_t w_id,
      bool bad_credit,
      Customer* customer)
    {
      customer->c_id = id;
      customer->c_d_id = d_id;
      customer->c_w_id = w_id;
      customer->c_credit_lim = Customer::INITIAL_CREDIT_LIM;
      customer->c_discount = random_float(Customer::MIN_DISCOUNT, Customer::MAX_DISCOUNT);
      customer->c_balance = Customer::INITIAL_BALANCE;
      customer->c_ytd_payment = Customer::INITIAL_YTD_PAYMENT;
      customer->c_payment_cnt = Customer::INITIAL_PAYMENT_CNT;
      customer->c_delivery_cnt = Customer::INITIAL_DELIVERY_CNT;
      create_random_string(
        customer->c_first, Customer::MIN_FIRST, Customer::MAX_FIRST);
      std::copy_n("OE", 3, customer->c_middle.begin());

      if (id <= 1000)
      {
        make_last_name(id - 1, customer->c_last.data());
      }
      else
      {
        make_last_name(random_int(0, 1000), customer->c_last.data());
      }

      create_random_string(
        customer->c_street_1, Address::MIN_STREET, Address::MAX_STREET);
      create_random_string(
        customer->c_street_2, Address::MIN_STREET, Address::MAX_STREET);
      create_random_string(customer->c_city, Address::MIN_CITY, Address::MAX_CITY);
      create_random_string(customer->c_state, Address::STATE, Address::STATE);
      create_random_string(customer->c_zip, Address::ZIP);
      create_random_int(customer->c_phone, Customer::PHONE);
      customer->c_since = tx_time;
      if (bad_credit)
      {
        std::copy_n(
          Customer::BAD_CREDIT,
          sizeof(Customer::BAD_CREDIT),
          customer->c_credit.begin());
      }
      else
      {
        std::copy_n(
          Customer::GOOD_CREDIT,
          sizeof(Customer::GOOD_CREDIT),
          customer->c_credit.begin());
      }
      create_random_string(
        customer->c_data, Customer::MIN_DATA, Customer::MAX_DATA);
    }

    void generate_history(
      int32_t c_id, int32_t d_id, int32_t w_id, History* history)
    {
      history->h_c_id = c_id;
      history->h_c_d_id = d_id;
      history->h_d_id = d_id;
      history->h_c_w_id = w_id;
      history->h_w_id = w_id;
      history->h_amount = History::INITIAL_AMOUNT;
      history->h_date = tx_time;
      create_random_string(history->h_data, History::MIN_DATA, History::MAX_DATA);
    }

    std::vector<int> make_permutation(int lower, int upper)
    {
      // initialize with consecutive values
      std::vector<int> array;
      array.resize(upper);
      for (int i = 0; i <= upper - lower; ++i)
      {
        array[i] = lower + i;
      }

      for (int i = 0; i < upper - lower; ++i)
      {
        // choose a value to go into this position, including this position
        int index = random_int(i, upper - lower);
        int temp = array[i];
        array[i] = array[index];
        array[index] = temp;
      }

      return array;
    }

    void generate_order(
      int32_t id,
      int32_t c_id,
      int32_t d_id,
      int32_t w_id,
      bool new_order,
      Order* order)
    {
      order->o_id = id;
      order->o_c_id = c_id;
      order->o_d_id = d_id;
      order->o_w_id = w_id;
      if (!new_order)
      {
        order->o_carrier_id =
          random_int(Order::MIN_CARRIER_ID, Order::MAX_CARRIER_ID);
      }
      else
      {
        order->o_carrier_id = Order::NULL_CARRIER_ID;
      }
      order->o_ol_cnt = random_int(Order::MIN_OL_CNT, Order::MAX_OL_CNT);
      order->o_all_local = Order::INITIAL_ALL_LOCAL;
      order->o_entry_d = tx_time;
    }

    void generate_order_line(
      int32_t number,
      int32_t o_id,
      int32_t d_id,
      int32_t w_id,
      bool new_order,
      OrderLine* orderline)
    {
      orderline->ol_o_id = o_id;
      orderline->ol_d_id = d_id;
      orderline->ol_w_id = w_id;
      orderline->ol_number = number;
      orderline->ol_i_id =
        random_int(OrderLine::MIN_I_ID, OrderLine::MAX_I_ID);
      orderline->ol_supply_w_id = w_id;
      orderline->ol_quantity = OrderLine::INITIAL_QUANTITY;
      if (!new_order)
      {
        orderline->ol_amount = 0.00;
        orderline->ol_delivery_d = tx_time;
      }
      else
      {
        orderline->ol_amount =
          random_float( OrderLine::MIN_AMOUNT, OrderLine::MAX_AMOUNT);
        orderline->ol_delivery_d[0] = '\0';
      }
      create_random_string(
        orderline->ol_dist_info,
        sizeof(orderline->ol_dist_info) - 1,
        sizeof(orderline->ol_dist_info) - 1);
    }

    void make_warehouse_without_stock(int32_t w_id)
    {
      Warehouse w;
      generate_warehouse(w_id, &w);
      auto warehouses = args.tx.rw(tpcc::TpccTables::warehouses);
      warehouses->put(w.get_key(), w);

      for (int32_t d_id = 1; d_id <= districts_per_warehouse; ++d_id)
      {
        District d;
        generate_district(d_id, w_id, &d);
        auto districts = args.tx.rw(tpcc::TpccTables::districts);
        districts->put(d.get_key(), d);

        // Select 10% of the customers to have bad credit
        std::unordered_set<uint32_t> selected_rows = select_unique_ids(
          customers_per_district / 10, customers_per_district);
        for (int32_t c_id = 1; c_id <= customers_per_district; ++c_id)
        {
          Customer c;
          bool bad_credit = selected_rows.find(c_id) != selected_rows.end();
          generate_customer(c_id, d_id, w_id, bad_credit, &c);

          TpccTables::DistributeKey table_key;
          table_key.v.w_id = w_id;
          table_key.v.d_id = d_id;
          auto it = tpcc::TpccTables::customers.find(table_key.k);
          if (it == tpcc::TpccTables::customers.end())
          {
            std::string tbl_name = fmt::format("customer_{}_{}", w_id, d_id);
            auto r = tpcc::TpccTables::customers.insert(
              {table_key.k, kv::Map<Customer::Key, Customer>(tbl_name.c_str())});
            it = r.first;
          }

          auto customers = args.tx.rw(it->second);
          customers->put(c.get_key(), c);

          History h;
          generate_history(c_id, d_id, w_id, &h);
          auto history = args.tx.rw(tpcc::TpccTables::histories);
          history->put(h.get_key(), h);
        }

        // TPC-C 4.3.3.1. says that this should be a permutation of [1,
        // 3000]. But since it is for a c_id field, it seems to make sense to
        // have it be a permutation of the customers. For the "real" thing this
        // will be equivalent
        std::vector<int> permutation =
          make_permutation(1, customers_per_district);
        for (int32_t o_id = 1; o_id <= customers_per_district; ++o_id)
        {
          // The last new_orders_per_district_ orders are new
          bool new_order =
            customers_per_district - new_orders_per_district < o_id;
          Order o;
          generate_order(
            o_id, permutation[o_id - 1], d_id, w_id, new_order, &o);

          TpccTables::DistributeKey table_key;
          table_key.v.w_id = w_id;
          table_key.v.d_id = d_id;
          auto it = tpcc::TpccTables::orders.find(table_key.k);
          if (it == tpcc::TpccTables::orders.end())
          {
            std::string tbl_name = fmt::format("orders_{}_{}", w_id, d_id);
            auto r = tpcc::TpccTables::orders.insert(
              {table_key.k, kv::Map<Order::Key, Order>(tbl_name.c_str())});
            it = r.first;
          }

          auto order = args.tx.rw(it->second);
          order->put(o.get_key(), o);

          // Generate each OrderLine for the order
          for (int32_t ol_number = 1; ol_number <= o.o_ol_cnt; ++ol_number)
          {
            OrderLine line;
            generate_order_line(ol_number, o_id, d_id, w_id, new_order, &line);
            auto order_lines = args.tx.rw(tpcc::TpccTables::order_lines);
            order_lines->put(line.get_key(), line);

            if (new_order)
            {
              // This is a new order: make one for it

              TpccTables::DistributeKey table_key;
              table_key.v.w_id = w_id;
              table_key.v.d_id = d_id;
              auto it = tpcc::TpccTables::new_orders.find(table_key.k);
              if (it == tpcc::TpccTables::new_orders.end())
              {
                std::string tbl_name =
                  fmt::format("new_orders_{}_{}", w_id, d_id);
                auto r = tpcc::TpccTables::new_orders.insert(
                  {table_key.k,
                   kv::Map<NewOrder::Key, NewOrder>(tbl_name.c_str())});
                it = r.first;
              }

              NewOrder no;
              no.no_w_id = w_id;
              no.no_d_id = d_id;
              no.no_o_id = o_id;

              auto new_orders = args.tx.rw(it->second);
              new_orders->put(no.get_key(), no);
            }
          }
        }
      }
    }

    void generate_item(int32_t id, bool original)
    {
      Item item;
      item.i_id = id;
      item.i_im_id = random_int(Item::MIN_IM, Item::MAX_IM);
      item.i_price = random_float(Item::MIN_PRICE, Item::MAX_PRICE);
      create_random_string(item.i_name, Item::MIN_NAME, Item::MAX_NAME);
      create_random_string(item.i_data, Item::MIN_DATA, Item::MAX_DATA);

      if (original)
      {
        set_original(item.i_data);
      }
      auto items_table = args.tx.rw(tpcc::TpccTables::items);
      items_table->put(item.get_key(), item);
    }

    // Generates num_items items and inserts them into tables.
    void make_items()
    {
      // Select 10% of the rows to be marked "original"
      auto original_rows =
        select_unique_ids(num_items, num_items / 10);

      for (uint32_t i = 1; i <= num_items; ++i)
      {
        bool is_original = original_rows.find(i) != original_rows.end();
        generate_item(i, is_original);
      }
    }

    void run()
    {
      LOG_INFO_FMT("Start create");
      if (already_run)
      {
        throw std::logic_error("Can only create the database 1 time");
      }
      already_run = true;

      make_items();
      for (uint32_t i = 0; i < num_warehouses; ++i)
      {
        make_stock(i);
        make_warehouse_without_stock(i);
      }
      LOG_INFO_FMT("end create");
    }
  };
}