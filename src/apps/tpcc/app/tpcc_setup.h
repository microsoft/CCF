// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tpcc_common.h"
#include "tpcc_tables.h"

#include <exception>
#include <set>
#include <stdint.h>

namespace tpcc
{
  class SetupDb
  {
  private:
    ccf::endpoints::EndpointContext& args;
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
      return tpcc::random_int_excluding(
        lower, upper, excluding, rand_generator);
    }

    template <size_t T>
    void create_random_string(
      std::array<char, T>& str, uint32_t min, uint32_t max)
    {
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
        str[i] = 97 + random_int(0, 26); // lower case letters
      }
      str[length - 1] = '\0';
    }

    template <size_t T>
    void create_random_int(std::array<char, T>& str, uint32_t length)
    {
      for (uint32_t i = 0; i < length - 1; ++i)
      {
        str[i] = 48 + random_int(0, 10); // lower case letters
      }
      str[length - 1] = '\0';
    }

    std::unordered_set<uint32_t> select_unique_ids(
      uint32_t num_items_, uint32_t num_unique)
    {
      std::unordered_set<uint32_t> r;
      for (uint32_t i = 0; i < num_items_; ++i)
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
      s.i_id = item_id;
      s.w_id = wh_id;
      s.quantity = random_int(Stock::MIN_QUANTITY, Stock::MAX_QUANTITY);
      s.ytd = 0;
      s.order_cnt = 0;
      s.remote_cnt = 0;
      for (int i = 0; i < District::NUM_PER_WAREHOUSE; ++i)
      {
        create_random_string(s.dist[i], sizeof(s.dist[i]));
      }

      if (is_original)
      {
        set_original(s.data);
      }
      else
      {
        create_random_string(
          s.data, random_int(Stock::MIN_DATA, Stock::MAX_DATA));
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
      warehouse->id = id;
      warehouse->tax = random_float(Warehouse::MIN_TAX, Warehouse::MAX_TAX);
      warehouse->ytd = Warehouse::INITIAL_YTD;
      create_random_string(
        warehouse->name, random_int(Warehouse::MIN_NAME, Warehouse::MAX_NAME));
      create_random_string(
        warehouse->street_1,
        random_int(Address::MIN_STREET, Address::MAX_STREET));
      create_random_string(
        warehouse->street_2,
        random_int(Address::MIN_STREET, Address::MAX_STREET));
      create_random_string(
        warehouse->city, random_int(Address::MIN_CITY, Address::MAX_CITY));
      create_random_string(warehouse->state, Address::STATE, Address::STATE);
      create_random_string(warehouse->zip, Address::ZIP);
    }

    void generate_district(int32_t id, int32_t w_id, District* district)
    {
      district->id = id;
      district->w_id = w_id;
      district->tax = random_float(District::MIN_TAX, District::MAX_TAX);
      district->ytd = District::INITIAL_YTD;
      district->next_o_id = customers_per_district + 1;
      create_random_string(
        district->name, District::MIN_NAME, District::MAX_NAME);
      create_random_string(
        district->street_1, Address::MIN_STREET, Address::MAX_STREET);
      create_random_string(
        district->street_2, Address::MIN_STREET, Address::MAX_STREET);
      create_random_string(
        district->city, Address::MIN_CITY, Address::MAX_CITY);
      create_random_string(district->state, Address::STATE, Address::STATE);
      create_random_string(district->zip, Address::ZIP);
    }

    void generate_customer(
      int32_t id,
      int32_t d_id,
      int32_t w_id,
      bool bad_credit,
      Customer* customer)
    {
      customer->id = id;
      customer->d_id = d_id;
      customer->w_id = w_id;
      customer->credit_lim = Customer::INITIAL_CREDIT_LIM;
      customer->discount =
        random_float(Customer::MIN_DISCOUNT, Customer::MAX_DISCOUNT);
      customer->balance = Customer::INITIAL_BALANCE;
      customer->ytd_payment = Customer::INITIAL_YTD_PAYMENT;
      customer->payment_cnt = Customer::INITIAL_PAYMENT_CNT;
      customer->delivery_cnt = Customer::INITIAL_DELIVERY_CNT;
      create_random_string(
        customer->first, Customer::MIN_FIRST, Customer::MAX_FIRST);
      std::copy_n("OE", 2, customer->middle.begin());

      if (id <= 1000)
      {
        make_last_name(id - 1, customer->last.data());
      }
      else
      {
        make_last_name(random_int(0, 1000), customer->last.data());
      }

      create_random_string(
        customer->street_1, Address::MIN_STREET, Address::MAX_STREET);
      create_random_string(
        customer->street_2, Address::MIN_STREET, Address::MAX_STREET);
      create_random_string(
        customer->city, Address::MIN_CITY, Address::MAX_CITY);
      create_random_string(customer->state, Address::STATE, Address::STATE);
      create_random_string(customer->zip, Address::ZIP);
      create_random_int(customer->phone, Customer::PHONE);
      customer->since = tx_time;
      if (bad_credit)
      {
        std::copy_n(
          Customer::BAD_CREDIT,
          sizeof(Customer::BAD_CREDIT),
          customer->credit.data());
      }
      else
      {
        std::copy_n(
          Customer::GOOD_CREDIT,
          sizeof(Customer::GOOD_CREDIT),
          customer->credit.data());
      }
      create_random_string(
        customer->data, Customer::MIN_DATA, Customer::MAX_DATA);
    }

    void generate_history(
      int32_t c_id, int32_t d_id, int32_t w_id, History* history)
    {
      history->c_id = c_id;
      history->c_d_id = d_id;
      history->d_id = d_id;
      history->c_w_id = w_id;
      history->w_id = w_id;
      history->amount = History::INITIAL_AMOUNT;
      history->date = tx_time;
      create_random_string(history->data, History::MIN_DATA, History::MAX_DATA);
    }

    std::vector<int> make_permutation(int lower, int upper)
    {
      std::vector<int> array;
      array.resize(upper);
      for (int i = 0; i <= upper - lower; ++i)
      {
        array[i] = lower + i;
      }

      for (int i = 0; i < upper - lower; ++i)
      {
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
      order->id = id;
      order->c_id = c_id;
      order->d_id = d_id;
      order->w_id = w_id;
      if (!new_order)
      {
        order->carrier_id =
          random_int(Order::MIN_CARRIER_ID, Order::MAX_CARRIER_ID);
      }
      else
      {
        order->carrier_id = Order::NULL_CARRIER_ID;
      }
      order->ol_cnt = random_int(Order::MIN_OL_CNT, Order::MAX_OL_CNT);
      order->all_local = Order::INITIAL_ALL_LOCAL;
      order->entry_d = tx_time;
    }

    void generate_order_line(
      int32_t number,
      int32_t o_id,
      int32_t d_id,
      int32_t w_id,
      bool new_order,
      OrderLine* orderline)
    {
      orderline->o_id = o_id;
      orderline->d_id = d_id;
      orderline->w_id = w_id;
      orderline->number = number;
      orderline->i_id = random_int(OrderLine::MIN_I_ID, OrderLine::MAX_I_ID);
      orderline->supply_w_id = w_id;
      orderline->quantity = OrderLine::INITIAL_QUANTITY;
      if (!new_order)
      {
        orderline->amount = 0.00;
        orderline->delivery_d = tx_time;
      }
      else
      {
        orderline->amount =
          random_float(OrderLine::MIN_AMOUNT, OrderLine::MAX_AMOUNT);
        orderline->delivery_d[0] = '\0';
      }
      create_random_string(
        orderline->dist_info,
        sizeof(orderline->dist_info) - 1,
        sizeof(orderline->dist_info) - 1);
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

          tpcc::TpccTables::DistributeKey table_key;
          table_key.v.w_id = w_id;
          table_key.v.d_id = d_id;
          auto it = tpcc::TpccTables::customers.find(table_key.k);
          if (it == tpcc::TpccTables::customers.end())
          {
            std::string tbl_name = fmt::format("customer_{}_{}", w_id, d_id);
            auto r = tpcc::TpccTables::customers.insert(
              {table_key.k,
               TpccMap<Customer::Key, Customer>(tbl_name.c_str())});
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

          tpcc::TpccTables::DistributeKey table_key;
          table_key.v.w_id = w_id;
          table_key.v.d_id = d_id;
          auto it = tpcc::TpccTables::orders.find(table_key.k);
          if (it == tpcc::TpccTables::orders.end())
          {
            std::string tbl_name = fmt::format("orders_{}_{}", w_id, d_id);
            auto r = tpcc::TpccTables::orders.insert(
              {table_key.k, TpccMap<Order::Key, Order>(tbl_name.c_str())});
            it = r.first;
          }

          auto order = args.tx.rw(it->second);
          order->put(o.get_key(), o);

          // Generate each OrderLine for the order
          for (int32_t ol_number = 1; ol_number <= o.ol_cnt; ++ol_number)
          {
            OrderLine line;
            generate_order_line(ol_number, o_id, d_id, w_id, new_order, &line);
            auto order_lines = args.tx.rw(tpcc::TpccTables::order_lines);
            order_lines->put(line.get_key(), line);

            if (new_order)
            {
              tpcc::TpccTables::DistributeKey table_key_;
              table_key_.v.w_id = w_id;
              table_key_.v.d_id = d_id;
              auto it_ = tpcc::TpccTables::new_orders.find(table_key_.k);
              if (it_ == tpcc::TpccTables::new_orders.end())
              {
                std::string tbl_name =
                  fmt::format("new_orders_{}_{}", w_id, d_id);
                auto r = tpcc::TpccTables::new_orders.insert(
                  {table_key_.k,
                   TpccMap<NewOrder::Key, NewOrder>(tbl_name.c_str())});
                it_ = r.first;
              }

              NewOrder no;
              no.w_id = w_id;
              no.d_id = d_id;
              no.o_id = o_id;

              auto new_orders = args.tx.rw(it_->second);
              new_orders->put(no.get_key(), no);
            }
          }
        }
      }
    }

    void generate_item(int32_t id, bool original)
    {
      Item item;
      item.id = id;
      item.im_id = random_int(Item::MIN_IM, Item::MAX_IM);
      item.price = random_float(Item::MIN_PRICE, Item::MAX_PRICE);
      create_random_string(item.name, Item::MIN_NAME, Item::MAX_NAME);
      create_random_string(item.data, Item::MIN_DATA, Item::MAX_DATA);

      if (original)
      {
        set_original(item.data);
      }
      auto items_table = args.tx.rw(tpcc::TpccTables::items);
      items_table->put(item.get_key(), item);
    }

    // Generates num_items items and inserts them into tables.
    void make_items()
    {
      // Select 10% of the rows to be marked "original"
      auto original_rows = select_unique_ids(num_items, num_items / 10);

      for (uint32_t i = 1; i <= num_items; ++i)
      {
        bool is_original = original_rows.find(i) != original_rows.end();
        generate_item(i, is_original);
      }
    }

  public:
    SetupDb(
      ccf::endpoints::EndpointContext& args_,
      int32_t new_orders_per_district_,
      uint32_t seed) :
      args(args_),
      already_run(false),
      new_orders_per_district(new_orders_per_district_)
    {
      rand_generator.seed(seed);
    }

    void run()
    {
      CCF_APP_INFO("Start create");
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
      CCF_APP_INFO("end create");
    }
  };
}