// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tpcc_common.h"
#include "tpcc_output.h"
#include "tpcc_tables.h"

#include <cinttypes>
#include <string.h>
#include <vector>

namespace tpcc
{
  class TpccTransactions
  {
  private:
    ccf::endpoints::EndpointContext& args;
    std::mt19937 rand_generator;

    static constexpr int STOCK_LEVEL_ORDERS = 20;
    static constexpr float MIN_PAYMENT_AMOUNT = 1.00;
    static constexpr float MAX_PAYMENT_AMOUNT = 5000.00;
    static constexpr int32_t MAX_OL_QUANTITY = 10;
    static constexpr int32_t INVALID_QUANTITY = -1;
    static constexpr char INVALID_ITEM_STATUS[] = "Item number is not valid";

    District find_district(int32_t w_id, int32_t d_id)
    {
      District::Key key = {w_id, d_id};

      auto districts_table = args.tx.ro(tpcc::TpccTables::districts);
      auto districts = districts_table->get(key);

      if (!districts.has_value())
      {
        throw std::logic_error("district does not exist");
      }
      return districts.value();
    }

    std::optional<OrderLine> find_order_line(
      int32_t w_id, int32_t d_id, int32_t o_id, int32_t number)
    {
      OrderLine::Key key = {o_id, d_id, w_id, number};
      auto order_lines_table = args.tx.ro(tpcc::TpccTables::order_lines);
      return order_lines_table->get(key);
    }

    std::optional<Item> find_item(int32_t id)
    {
      Item::Key key = {id};
      auto items_table = args.tx.ro(tpcc::TpccTables::items);
      return items_table->get(key);
    }

    Stock find_stock(int32_t w_id, int32_t s_id)
    {
      Stock::Key key = {s_id, w_id};
      auto stocks_table = args.tx.ro(tpcc::TpccTables::stocks);
      auto stock = stocks_table->get(key);
      if (!stock.has_value())
      {
        throw std::logic_error("stock does not exist");
      }
      return stock.value();
    }

    Customer find_customer(int32_t w_id, int32_t d_id, int32_t c_id)
    {
      TpccTables::DistributeKey table_key;
      table_key.v.w_id = w_id;
      table_key.v.d_id = d_id;
      auto it = tpcc::TpccTables::customers.find(table_key.k);
      Customer::Key key = {c_id};
      auto customers_table = args.tx.ro(it->second);
      auto customers = customers_table->get(key);
      if (!customers.has_value())
      {
        throw std::logic_error("customers does not exist");
      }
      return customers.value();
    }

    Warehouse find_warehouse(int32_t w_id)
    {
      Warehouse::Key key = {w_id};
      auto warehouses_table = args.tx.ro(tpcc::TpccTables::warehouses);
      auto warehouse = warehouses_table->get(key);
      if (!warehouse.has_value())
      {
        throw std::logic_error("warehouse does not exist");
      }
      return warehouse.value();
    }

    void insert_order(Order& o)
    {
      TpccTables::DistributeKey table_key;
      table_key.v.w_id = o.w_id;
      table_key.v.d_id = o.d_id;
      auto it = tpcc::TpccTables::orders.find(table_key.k);
      auto orders_table = args.tx.rw(it->second);
      orders_table->put(o.get_key(), o);
    }

    void insert_new_order(int32_t w_id, int32_t d_id, int32_t o_id)
    {
      NewOrder no;
      no.w_id = w_id;
      no.d_id = d_id;
      no.o_id = o_id;

      TpccTables::DistributeKey table_key;
      table_key.v.w_id = w_id;
      table_key.v.d_id = d_id;
      auto it = tpcc::TpccTables::new_orders.find(table_key.k);

      auto new_orders_table = args.tx.rw(it->second);
      new_orders_table->put(no.get_key(), no);
    }

    void insert_order_line(OrderLine& line)
    {
      auto order_lines = args.tx.rw(tpcc::TpccTables::order_lines);
      order_lines->put(line.get_key(), line);
    }

    void order_status(
      int32_t warehouse_id,
      int32_t district_id,
      int32_t customer_id,
      OrderStatusOutput* output)
    {
      auto customer = find_customer(warehouse_id, district_id, customer_id);
      internal_order_status(customer, output);
    }

    Customer find_customer_by_name(
      int32_t w_id, int32_t d_id, const char* c_last)
    {
      Customer customer_ret;
      TpccTables::DistributeKey table_key;
      table_key.v.w_id = w_id;
      table_key.v.d_id = d_id;
      auto it = tpcc::TpccTables::customers.find(table_key.k);
      auto customers_table = args.tx.ro(it->second);
      customers_table->foreach([&](const Customer::Key&, const Customer& c) {
        if (strcmp(c.last.data(), c_last) == 0)
        {
          customer_ret = c;
          return false;
        }
        return true;
      });
      return customer_ret;
    }

    void order_status(
      int32_t warehouse_id,
      int32_t district_id,
      const char* c_last,
      OrderStatusOutput* output)
    {
      Customer customer =
        find_customer_by_name(warehouse_id, district_id, c_last);
      internal_order_status(customer, output);
    }

    Order find_last_order_by_customer(
      const int32_t w_id, const int32_t d_id, const int32_t c_id)
    {
      Order order;

      TpccTables::DistributeKey table_key;
      table_key.v.w_id = w_id;
      table_key.v.d_id = d_id;
      auto it = tpcc::TpccTables::orders.find(table_key.k);

      auto orders_table = args.tx.ro(it->second);
      orders_table->foreach([&](const Order::Key&, const Order& o) {
        if (o.c_id == c_id)
        {
          order = o;
          return false;
        }
        return true;
      });

      return order;
    }

    void internal_order_status(Customer& customer, OrderStatusOutput* output)
    {
      output->c_id = customer.id;
      // retrieve from customer: balance, first, middle, last
      output->c_balance = customer.balance;
      output->c_first = customer.first;
      output->c_middle = customer.middle;
      output->c_last = customer.last;

      // Find the row in the order table with largest o_id
      Order order =
        find_last_order_by_customer(customer.w_id, customer.d_id, customer.id);
      output->o_id = order.id;
      output->o_carrier_id = order.carrier_id;
      output->o_entry_d = order.entry_d;

      output->lines.resize(order.ol_cnt);
      for (int32_t line_number = 1; line_number <= order.ol_cnt; ++line_number)
      {
        OrderLine line =
          find_order_line(customer.w_id, customer.d_id, order.id, line_number)
            .value();
        output->lines[line_number - 1].i_id = line.i_id;
        output->lines[line_number - 1].supply_w_id = line.supply_w_id;
        output->lines[line_number - 1].quantity = line.quantity;
        output->lines[line_number - 1].amount = line.amount;
        output->lines[line_number - 1].delivery_d = line.delivery_d;
      }
    }

    int32_t generate_item_id()
    {
      return random_int(1, num_items);
    }

    int32_t generate_warehouse()
    {
      return random_int(1, num_warehouses);
    }

    int32_t generate_district()
    {
      return random_int(1, districts_per_warehouse);
    }

    int32_t generate_cid()
    {
      return random_int(1, customers_per_district);
    }

    Order find_order(int32_t w_id, int32_t d_id, int32_t o_id)
    {
      TpccTables::DistributeKey table_key;
      table_key.v.w_id = w_id;
      table_key.v.d_id = d_id;

      auto it = tpcc::TpccTables::orders.find(table_key.k);
      auto orders_table = args.tx.ro(it->second);
      Order::Key key = {o_id};
      auto order = orders_table->get(key);
      return order.value();
    }

    void delivery(
      int32_t warehouse_id,
      int32_t carrier_id,
      std::array<char, DATETIME_SIZE + 1>& now,
      std::vector<DeliveryOrderInfo>* orders)
    {
      for (int32_t d_id = 1; d_id <= District::NUM_PER_WAREHOUSE; ++d_id)
      {
        TpccTables::DistributeKey table_key;
        table_key.v.w_id = warehouse_id;
        table_key.v.d_id = d_id;
        auto it = tpcc::TpccTables::new_orders.find(table_key.k);

        auto new_orders_table = args.tx.rw(it->second);
        bool new_order_exists = false;
        NewOrder::Key new_order_key = {warehouse_id, d_id, 1};
        int32_t o_id;
        new_orders_table->foreach(
          [&](const NewOrder::Key& k, const NewOrder& no) {
            new_order_key = k;
            o_id = no.o_id;
            new_order_exists = true;
            return false;
          });
        if (!new_order_exists)
        {
          continue;
        }
        new_orders_table->remove(new_order_key);

        DeliveryOrderInfo order;
        order.d_id = d_id;
        order.o_id = o_id;
        orders->push_back(order);

        Order o = find_order(warehouse_id, d_id, o_id);
        o.carrier_id = carrier_id;

        float total = 0;
        for (int32_t i = 1; i <= o.ol_cnt; ++i)
        {
          std::optional<OrderLine> line =
            find_order_line(warehouse_id, d_id, o_id, i);
          line->delivery_d = now;
          total += line->amount;
        }

        Customer c = find_customer(warehouse_id, d_id, o.c_id);
        c.balance += total;
        c.delivery_cnt += 1;
      }
    }

    void payment_home(
      int32_t warehouse_id,
      int32_t district_id,
      int32_t c_warehouse_id,
      int32_t c_district_id,
      int32_t customer_id,
      float h_amount,
      std::array<char, DATETIME_SIZE + 1> now,
      PaymentOutput* output)
    {
      Warehouse w = find_warehouse(warehouse_id);
      w.ytd += h_amount;
      output->w_street_1 = w.street_1;
      output->w_street_2 = w.street_2;
      output->w_city = w.city;
      output->w_state = w.state;
      output->w_zip = w.zip;

      District d = find_district(warehouse_id, district_id);
      d.ytd += h_amount;

      output->d_street_1 = d.street_1;
      output->d_street_2 = d.street_2;
      output->d_city = d.city;
      output->d_state = d.state;
      output->d_zip = d.zip;

      // Insert the line into the history table
      History h;
      h.w_id = warehouse_id;
      h.d_id = district_id;
      h.c_w_id = c_warehouse_id;
      h.c_d_id = c_district_id;
      h.c_id = customer_id;
      h.amount = h_amount;
      h.date = now;
      std::copy_n(h.data.data(), w.name.size(), w.name.data());
      // strcat(h.data.data(), "    ");

      auto history_table = args.tx.rw(tpcc::TpccTables::histories);
      history_table->put(h.get_key(), h);
    }

    void internal_payment_remote(
      int32_t warehouse_id,
      int32_t district_id,
      Customer& c,
      float h_amount,
      PaymentOutput* output)
    {
      c.balance -= h_amount;
      c.ytd_payment += h_amount;
      c.payment_cnt += 1;
      if (strcmp(c.credit.data(), Customer::BAD_CREDIT) == 0)
      {
        // Bad credit: insert history into c_data
        static const int HISTORY_SIZE = Customer::MAX_DATA + 1;
        std::array<char, HISTORY_SIZE> history;
        int characters = snprintf(
          history.data(),
          HISTORY_SIZE,
          "(%d, %d, %d, %d, %d, %.2f)\n",
          c.id,
          c.d_id,
          c.w_id,
          district_id,
          warehouse_id,
          h_amount);

        // Perform the insert with a move and copy
        int current_keep = static_cast<int>(strlen(c.data.data()));
        if (current_keep + characters > Customer::MAX_DATA)
        {
          current_keep = Customer::MAX_DATA - characters;
        }
        memmove(c.data.data() + characters, c.data.data(), current_keep);
        memcpy(c.data.data(), history.data(), characters);
        c.data[characters + current_keep] = '\0';
      }

      output->c_credit_lim = c.credit_lim;
      output->c_discount = c.discount;
      output->c_balance = c.balance;
      output->c_first = c.first;
      output->c_middle = c.middle;
      output->c_last = c.last;
      output->c_street_1 = c.street_1;
      output->c_street_2 = c.street_2;
      output->c_city = c.city;
      output->c_state = c.state;
      output->c_zip = c.zip;
      output->c_phone = c.phone;
      output->c_since = c.since;
      output->c_credit = c.credit;
      output->c_data = c.data;
    }

    void payment(
      int32_t warehouse_id,
      int32_t district_id,
      int32_t c_warehouse_id,
      int32_t c_district_id,
      int32_t customer_id,
      float h_amount,
      std::array<char, DATETIME_SIZE + 1> now,
      PaymentOutput* output)
    {
      // c_warehouse_id, c_district_id, customer_id, h_amount, now);
      Customer customer =
        find_customer(c_warehouse_id, c_district_id, customer_id);
      payment_home(
        warehouse_id,
        district_id,
        c_warehouse_id,
        c_district_id,
        customer_id,
        h_amount,
        now,
        output);
      internal_payment_remote(
        warehouse_id, district_id, customer, h_amount, output);
    }

    void payment(
      int32_t warehouse_id,
      int32_t district_id,
      int32_t c_warehouse_id,
      int32_t c_district_id,
      std::array<char, Customer::MAX_LAST + 1> c_last,
      float h_amount,
      std::array<char, DATETIME_SIZE + 1> now,
      PaymentOutput* output)
    {
      Customer customer =
        find_customer_by_name(c_warehouse_id, c_district_id, c_last.data());
      payment_home(
        warehouse_id,
        district_id,
        c_warehouse_id,
        c_district_id,
        customer.id,
        h_amount,
        now,
        output);
      internal_payment_remote(
        warehouse_id, district_id, customer, h_amount, output);
    }

    void new_order_combine(
      const std::vector<int32_t>& remote_quantities, NewOrderOutput* output)
    {
      for (size_t i = 0; i < remote_quantities.size(); ++i)
      {
        if (remote_quantities[i] != INVALID_QUANTITY)
        {
          output->items[i].s_quantity = remote_quantities[i];
        }
      }
    }

    void new_order_combine(
      const std::vector<int32_t>& remote_quantities,
      std::vector<int32_t>* output)
    {
      for (size_t i = 0; i < remote_quantities.size(); ++i)
      {
        if (remote_quantities[i] != INVALID_QUANTITY)
        {
          (*output)[i] = remote_quantities[i];
        }
      }
    }

    bool new_order_remote(
      int32_t home_warehouse,
      int32_t remote_warehouse,
      const std::vector<NewOrderItem>& items,
      std::vector<int32_t>* out_quantities)
    {
      out_quantities->resize(items.size());
      for (uint32_t i = 0; i < items.size(); ++i)
      {
        // Skip items that don't belong to remote warehouse
        if (items[i].ol_supply_w_id != remote_warehouse)
        {
          (*out_quantities)[i] = INVALID_QUANTITY;
          continue;
        }

        // update stock
        Stock stock = find_stock(items[i].ol_supply_w_id, items[i].i_id);
        if (stock.quantity >= items[i].ol_quantity + 10)
        {
          stock.quantity -= items[i].ol_quantity;
        }
        else
        {
          stock.quantity = stock.quantity - items[i].ol_quantity + 91;
        }
        (*out_quantities)[i] = stock.quantity;
        stock.ytd += items[i].ol_quantity;
        stock.order_cnt += 1;

        if (items[i].ol_supply_w_id != home_warehouse)
        {
          stock.remote_cnt += 1;
        }
      }

      return true;
    }

    std::set<int32_t> new_order_remote_warehouses(
      int32_t home_warehouse, const std::vector<NewOrderItem>& items)
    {
      std::set<int32_t> out;
      for (size_t i = 0; i < items.size(); ++i)
      {
        if (items[i].ol_supply_w_id != home_warehouse)
        {
          out.insert(items[i].ol_supply_w_id);
        }
      }
      return out;
    }

    bool new_order(
      int32_t warehouse_id,
      int32_t district_id,
      int32_t customer_id,
      const std::vector<NewOrderItem>& items,
      std::array<char, DATETIME_SIZE + 1> now,
      NewOrderOutput* output)
    {
      // perform the home part
      bool result = new_order_home(
        warehouse_id, district_id, customer_id, items, now, output);
      if (!result)
      {
        return false;
      }

      // Process all remote warehouses
      std::set<int32_t> warehouses =
        new_order_remote_warehouses(warehouse_id, items);
      for (auto i = warehouses.begin(); i != warehouses.end(); ++i)
      {
        std::vector<int32_t> quantities;
        result = new_order_remote(warehouse_id, *i, items, &quantities);
        assert(result);
        new_order_combine(quantities, output);
      }

      return true;
    }

    bool find_and_validate_items(
      const std::vector<NewOrderItem>& items,
      std::vector<std::optional<Item>>* item_tuples)
    {
      // CHEAT: Validate all items to see if we will need to abort
      item_tuples->resize(items.size());
      for (uint32_t i = 0; i < items.size(); ++i)
      {
        (*item_tuples)[i] = find_item(items[i].i_id);
        if (!(*item_tuples)[i].has_value())
        {
          return false;
        }
      }
      return true;
    }

    bool new_order_home(
      int32_t warehouse_id,
      int32_t district_id,
      int32_t customer_id,
      const std::vector<NewOrderItem>& items,
      std::array<char, DATETIME_SIZE + 1> now,
      NewOrderOutput* output)
    {
      // 2.4.3.4. requires that we display c_last, c_credit, and o_id for rolled
      // back transactions: read those values first
      District d = find_district(warehouse_id, district_id);
      output->d_tax = d.tax;
      output->o_id = d.next_o_id;

      Customer c = find_customer(warehouse_id, district_id, customer_id);
      output->c_last = c.last;
      output->c_credit = c.credit;
      output->c_discount = c.discount;

      // CHEAT: Validate all items to see if we will need to abort
      std::vector<std::optional<Item>> item_tuples(items.size());
      if (!find_and_validate_items(items, &item_tuples))
      {
        strcpy(output->status.data(), INVALID_ITEM_STATUS);
        return false;
      }

      // Check if this is an all local transaction
      bool all_local = true;
      for (size_t i = 0; i < items.size(); ++i)
      {
        if (items[i].ol_supply_w_id != warehouse_id)
        {
          all_local = false;
          break;
        }
      }

      output->status[0] = '\0';
      d.next_o_id += 1;

      Warehouse w = find_warehouse(warehouse_id);
      output->w_tax = w.tax;

      Order order;
      order.w_id = warehouse_id;
      order.d_id = district_id;
      order.id = output->o_id;
      order.c_id = customer_id;
      order.carrier_id = Order::NULL_CARRIER_ID;
      order.ol_cnt = static_cast<int32_t>(items.size());
      order.all_local = all_local ? 1 : 0;
      order.entry_d = now;
      insert_order(order);
      insert_new_order(warehouse_id, district_id, output->o_id);

      OrderLine line;
      line.o_id = output->o_id;
      line.d_id = district_id;
      line.w_id = warehouse_id;
      memset(line.delivery_d.data(), 0, DATETIME_SIZE + 1);

      output->items.resize(items.size());
      output->total = 0;
      for (uint32_t i = 0; i < items.size(); ++i)
      {
        line.number = i + 1;
        line.i_id = items[i].i_id;
        line.supply_w_id = items[i].ol_supply_w_id;
        line.quantity = items[i].ol_quantity;

        Stock stock = find_stock(items[i].ol_supply_w_id, items[i].i_id);
        memcpy(
          line.dist_info.data(),
          stock.dist[district_id].data(),
          sizeof(line.dist_info));

        bool stock_is_original =
          (strstr(stock.data.data(), "ORIGINAL") != NULL);
        if (
          stock_is_original &&
          strstr(item_tuples[i]->data.data(), "ORIGINAL") != NULL)
        {
          output->items[i].brand_generic = NewOrderOutput::ItemInfo::BRAND;
        }
        else
        {
          output->items[i].brand_generic = NewOrderOutput::ItemInfo::GENERIC;
        }

        output->items[i].i_name = item_tuples[i]->name;
        output->items[i].i_price = item_tuples[i]->price;
        output->items[i].ol_amount =
          static_cast<float>(items[i].ol_quantity) * item_tuples[i]->price;
        line.amount = output->items[i].ol_amount;
        output->total += output->items[i].ol_amount;
        insert_order_line(line);
      }

      std::vector<int32_t> quantities;
      new_order_remote(warehouse_id, warehouse_id, items, &quantities);
      new_order_combine(quantities, output);

      return true;
    }

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

  public:
    TpccTransactions(ccf::endpoints::EndpointContext& args_, uint32_t seed) :
      args(args_)
    {
      rand_generator.seed(seed);
    }

    int32_t stock_level(
      int32_t warehouse_id, int32_t district_id, int32_t threshold)
    {
      District d = find_district(warehouse_id, district_id);
      int32_t o_id = d.next_o_id;

      std::vector<int32_t> s_i_ids;
      s_i_ids.reserve(300);

      for (int order_id = o_id - STOCK_LEVEL_ORDERS; order_id < o_id;
           ++order_id)
      {
        for (int line_number = 1; line_number <= Order::MAX_OL_CNT;
             ++line_number)
        {
          std::optional<OrderLine> line_ret =
            find_order_line(warehouse_id, district_id, order_id, line_number);
          if (!line_ret.has_value())
          {
            break;
          }
          auto& line = line_ret.value();

          // Check if s_quantity < threshold
          Stock stock = find_stock(warehouse_id, line.i_id);
          if (stock.quantity < threshold)
          {
            s_i_ids.push_back(line.i_id);
          }
        }
      }

      std::sort(s_i_ids.begin(), s_i_ids.end());
      int num_distinct = 0;
      int32_t last = -1;
      for (size_t i = 0; i < s_i_ids.size(); ++i)
      {
        if (s_i_ids[i] != last)
        {
          last = s_i_ids[i];
          num_distinct += 1;
        }
      }
      return num_distinct;
    }

    void order_status()
    {
      OrderStatusOutput output;
      int y = random_int(0, 100);
      if (y <= 60)
      {
        // 60%: order status by last name
        char c_last[Customer::MAX_LAST + 1];
        tpcc::make_last_name(random_int(1, customers_per_district), c_last);
        uint32_t w_id = generate_warehouse();
        uint32_t d_id = generate_district();
        order_status(w_id, d_id, c_last, &output);
      }
      else
      {
        // 40%: order status by id
        order_status(
          generate_warehouse(), generate_district(), generate_cid(), &output);
      }
    }

    void delivery()
    {
      int carrier = random_int(Order::MIN_CARRIER_ID, Order::MAX_CARRIER_ID);
      std::array<char, DATETIME_SIZE + 1> now = tx_time;

      std::vector<DeliveryOrderInfo> orders;
      delivery(generate_warehouse(), carrier, now, &orders);
    }

    void payment()
    {
      PaymentOutput output;
      int x = random_int(1, 100);
      int y = random_int(1, 100);

      int32_t w_id = generate_warehouse();
      int32_t d_id = generate_district();

      int32_t c_w_id;
      int32_t c_d_id;
      if (num_warehouses == 1 || x <= 85)
      {
        // 85%: paying through own warehouse (or there is only 1 warehouse)
        c_w_id = w_id;
        c_d_id = d_id;
      }
      else
      {
        // 15%: paying through another warehouse:
        c_w_id = random_int_excluding(1, num_warehouses, w_id);
        c_d_id = generate_district();
      }
      float h_amount = random_float(MIN_PAYMENT_AMOUNT, MAX_PAYMENT_AMOUNT);

      std::array<char, DATETIME_SIZE + 1> now = tx_time;
      if (y <= 60)
      {
        // 60%: payment by last name
        std::array<char, Customer::MAX_LAST + 1> c_last;
        make_last_name(random_int(1, customers_per_district), c_last.data());
        payment(w_id, d_id, c_w_id, c_d_id, c_last, h_amount, now, &output);
      }
      else
      {
        // 40%: payment by id
        payment(
          w_id, d_id, c_w_id, c_d_id, generate_cid(), h_amount, now, &output);
      }
    }

    bool new_order()
    {
      int32_t w_id = generate_warehouse();
      int ol_cnt = random_int(Order::MIN_OL_CNT, Order::MAX_OL_CNT);

      // 1% of transactions roll back
      bool rollback = random_int(1, 100) == 1;

      std::vector<NewOrderItem> items(ol_cnt);
      for (int i = 0; i < ol_cnt; ++i)
      {
        if (rollback && i + 1 == ol_cnt)
        {
          items[i].i_id = Item::NUM_ITEMS + 1;
        }
        else
        {
          items[i].i_id = generate_item_id();
        }

        // TPC-C suggests generating a number in range (1, 100) and selecting
        // remote on 1
        bool remote = (random_int(1, 100) == 1);
        if (num_warehouses > 1 && remote)
        {
          items[i].ol_supply_w_id =
            random_int_excluding(1, num_warehouses, w_id);
        }
        else
        {
          items[i].ol_supply_w_id = w_id;
        }
        items[i].ol_quantity = random_int(1, MAX_OL_QUANTITY);
      }

      std::array<char, DATETIME_SIZE + 1> now = tx_time;
      NewOrderOutput output;
      bool result = new_order(
        w_id, generate_district(), generate_cid(), items, now, &output);
      return result;
    }
  };
}