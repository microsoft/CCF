#pragma once

#include "tpcc_common.h"
#include "tpcc_tables.h"

#include <cinttypes>
#include <string.h>
#include <vector>

namespace tpcc
{
  class TpccTransactions
  {
  private:
    ccf::EndpointContext& args;
    static constexpr int STOCK_LEVEL_ORDERS = 20;
    static constexpr float MIN_PAYMENT_AMOUNT = 1.00;
    static constexpr float MAX_PAYMENT_AMOUNT = 5000.00;
    static constexpr int32_t MAX_OL_QUANTITY = 10;
    static constexpr int32_t INVALID_QUANTITY = -1;
    static constexpr char INVALID_ITEM_STATUS[] = "Item number is not valid";
    static constexpr std::array<char, tpcc::DATETIME_SIZE + 1> tx_time = {"12345 time"};

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
      table_key.v.w_id = o.o_w_id;
      table_key.v.d_id = o.o_d_id;
      auto it = tpcc::TpccTables::orders.find(table_key.k);
      auto orders_table = args.tx.rw(it->second);
      orders_table->put(o.get_key(), o);
    }

    void insert_new_order(int32_t w_id, int32_t d_id, int32_t o_id)
    {
      NewOrder no;
      no.no_w_id = w_id;
      no.no_d_id = d_id;
      no.no_o_id = o_id;

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
      // select (w_id, d_id, *, c_last) order by c_first
      Customer customer_ret;
      TpccTables::DistributeKey table_key;
      table_key.v.w_id = w_id;
      table_key.v.d_id = d_id;
      auto it = tpcc::TpccTables::customers.find(table_key.k);
      auto customers_table = args.tx.ro(it->second);
      customers_table->foreach([&](const Customer::Key&, const Customer& c) {
        if (strcmp(c.c_last.data(), c_last) == 0)
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
        if (o.o_c_id == c_id)
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
      output->c_id = customer.c_id;
      // retrieve from customer: balance, first, middle, last
      output->c_balance = customer.c_balance;
      output->c_first = customer.c_first;
      output->c_middle = customer.c_middle;
      output->c_last = customer.c_last;

      // Find the row in the order table with largest o_id
      Order order = find_last_order_by_customer(
        customer.c_w_id, customer.c_d_id, customer.c_id);
      output->o_id = order.o_id;
      output->o_carrier_id = order.o_carrier_id;
      output->o_entry_d = order.o_entry_d;

      output->lines.resize(order.o_ol_cnt);
      for (int32_t line_number = 1; line_number <= order.o_ol_cnt;
           ++line_number)
      {
        OrderLine line =
          find_order_line(
            customer.c_w_id, customer.c_d_id, order.o_id, line_number)
            .value();
        output->lines[line_number - 1].ol_i_id = line.ol_i_id;
        output->lines[line_number - 1].ol_supply_w_id = line.ol_supply_w_id;
        output->lines[line_number - 1].ol_quantity = line.ol_quantity;
        output->lines[line_number - 1].ol_amount = line.ol_amount;
        output->lines[line_number - 1].ol_delivery_d = line.ol_delivery_d;
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
        new_orders_table->foreach([&](const NewOrder::Key& k, const NewOrder& no) {
          new_order_key = k;
          o_id = no.no_o_id;
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
        o.o_carrier_id = carrier_id;

        float total = 0;
        for (int32_t i = 1; i <= o.o_ol_cnt; ++i)
        {
          std::optional<OrderLine> line =
            find_order_line(warehouse_id, d_id, o_id, i);
          line->ol_delivery_d = now;
          total += line->ol_amount;
        }

        Customer c = find_customer(warehouse_id, d_id, o.o_c_id);
        c.c_balance += total;
        c.c_delivery_cnt += 1;
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
      w.w_ytd += h_amount;
      output->w_street_1 = w.w_street_1;
      output->w_street_2 = w.w_street_2;
      output->w_city = w.w_city;
      output->w_state = w.w_state;
      output->w_zip = w.w_zip;

      District d = find_district(warehouse_id, district_id);
      d.d_ytd += h_amount;

      output->d_street_1 = d.d_street_1;
      output->d_street_2 = d.d_street_2;
      output->d_city = d.d_city;
      output->d_state = d.d_state;
      output->d_zip = d.d_zip;

      // Insert the line into the history table
      History h;
      h.h_w_id = warehouse_id;
      h.h_d_id = district_id;
      h.h_c_w_id = c_warehouse_id;
      h.h_c_d_id = c_district_id;
      h.h_c_id = customer_id;
      h.h_amount = h_amount;
      h.h_date = now;
      std::copy_n(h.h_data.data(), w.w_name.size(), w.w_name.data());
      strcat(h.h_data.data(), "    ");

      History::Key history_key = {
        h.h_c_id, h.h_c_d_id, h.h_c_w_id, h.h_d_id, h.h_w_id};
      auto history_table = args.tx.rw(tpcc::TpccTables::histories);
      history_table->put(history_key, h);
    }

    void internal_payment_remote(
      int32_t warehouse_id,
      int32_t district_id,
      Customer& c,
      float h_amount,
      PaymentOutput* output)
    {
      c.c_balance -= h_amount;
      c.c_ytd_payment += h_amount;
      c.c_payment_cnt += 1;
      if (strcmp(c.c_credit.data(), Customer::BAD_CREDIT) == 0)
      {
        // Bad credit: insert history into c_data
        static const int HISTORY_SIZE = Customer::MAX_DATA + 1;
        std::array<char, HISTORY_SIZE> history;
        int characters = snprintf(
          history.data(),
          HISTORY_SIZE,
          "(%d, %d, %d, %d, %d, %.2f)\n",
          c.c_id,
          c.c_d_id,
          c.c_w_id,
          district_id,
          warehouse_id,
          h_amount);

        // Perform the insert with a move and copy
        int current_keep = static_cast<int>(strlen(c.c_data.data()));
        if (current_keep + characters > Customer::MAX_DATA)
        {
          current_keep = Customer::MAX_DATA - characters;
        }
        memmove(c.c_data.data() + characters, c.c_data.data(), current_keep);
        memcpy(c.c_data.data(), history.data(), characters);
        c.c_data[characters + current_keep] = '\0';
      }

      output->c_credit_lim = c.c_credit_lim;
      output->c_discount = c.c_discount;
      output->c_balance = c.c_balance;
      output->c_first = c.c_first;
      output->c_middle = c.c_middle;
      output->c_last = c.c_last;
      output->c_street_1 = c.c_street_1;
      output->c_street_2 = c.c_street_2;
      output->c_city = c.c_city;
      output->c_state = c.c_state;
      output->c_zip = c.c_zip;
      output->c_phone = c.c_phone;
      output->c_since = c.c_since;
      output->c_credit = c.c_credit;
      output->c_data = c.c_data;
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
        customer.c_id,
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
        if (stock.s_quantity >= items[i].ol_quantity + 10)
        {
          stock.s_quantity -= items[i].ol_quantity;
        }
        else
        {
          stock.s_quantity = stock.s_quantity - items[i].ol_quantity + 91;
        }
        (*out_quantities)[i] = stock.s_quantity;
        stock.s_ytd += items[i].ol_quantity;
        stock.s_order_cnt += 1;

        if (items[i].ol_supply_w_id != home_warehouse)
        {
          stock.s_remote_cnt += 1;
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
      std::set<int32_t> warehouses = new_order_remote_warehouses(warehouse_id, items);
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
      const std::vector<NewOrderItem>& items, std::vector<std::optional<Item>>* item_tuples)
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
      output->d_tax = d.d_tax;
      output->o_id = d.d_next_o_id;

      Customer c = find_customer(warehouse_id, district_id, customer_id);
      output->c_last = c.c_last;
      output->c_credit = c.c_credit;
      output->c_discount = c.c_discount;

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
      d.d_next_o_id += 1;

      Warehouse w = find_warehouse(warehouse_id);
      output->w_tax = w.w_tax;

      Order order;
      order.o_w_id = warehouse_id;
      order.o_d_id = district_id;
      order.o_id = output->o_id;
      order.o_c_id = customer_id;
      order.o_carrier_id = Order::NULL_CARRIER_ID;
      order.o_ol_cnt = static_cast<int32_t>(items.size());
      order.o_all_local = all_local ? 1 : 0;
      order.o_entry_d =  now;
      insert_order(order);
      insert_new_order(warehouse_id, district_id, output->o_id);

      OrderLine line;
      line.ol_o_id = output->o_id;
      line.ol_d_id = district_id;
      line.ol_w_id = warehouse_id;
      memset(line.ol_delivery_d.data(), 0, DATETIME_SIZE + 1);

      output->items.resize(items.size());
      output->total = 0;
      for (uint32_t i = 0; i < items.size(); ++i)
      {
        line.ol_number = i + 1;
        line.ol_i_id = items[i].i_id;
        line.ol_supply_w_id = items[i].ol_supply_w_id;
        line.ol_quantity = items[i].ol_quantity;

        Stock stock = find_stock(items[i].ol_supply_w_id, items[i].i_id);
        memcpy(
          line.ol_dist_info.data(),
          stock.s_dist[district_id].data(),
          sizeof(line.ol_dist_info));

        bool stock_is_original = (strstr(stock.s_data.data(), "ORIGINAL") != NULL);
        if (
          stock_is_original &&
          strstr(item_tuples[i]->i_data.data(), "ORIGINAL") != NULL)
        {
          output->items[i].brand_generic = NewOrderOutput::ItemInfo::BRAND;
        }
        else
        {
          output->items[i].brand_generic = NewOrderOutput::ItemInfo::GENERIC;
        }

        output->items[i].i_name = item_tuples[i]->i_name;
        output->items[i].i_price = item_tuples[i]->i_price;
        output->items[i].ol_amount =
          static_cast<float>(items[i].ol_quantity) * item_tuples[i]->i_price;
        line.ol_amount = output->items[i].ol_amount;
        output->total += output->items[i].ol_amount;
        insert_order_line(line);
      }

      std::vector<int32_t> quantities;
        new_order_remote(warehouse_id, warehouse_id, items, &quantities);
      new_order_combine(quantities, output);

      return true;
    }

  public:
    TpccTransactions(ccf::EndpointContext& args_) : args(args_) {}

    int32_t stock_level(
      int32_t warehouse_id, int32_t district_id, int32_t threshold)
    {
      /* EXEC SQL SELECT d_next_o_id INTO :o_id FROM district
          WHERE d_w_id=:w_id AND d_id=:d_id; */
      District d = find_district(warehouse_id, district_id);
      int32_t o_id = d.d_next_o_id;

      /* EXEC SQL SELECT COUNT(DISTINCT (s_i_id)) INTO :stock_count FROM
         order_line, stock WHERE ol_w_id=:w_id AND ol_d_id=:d_id AND
         ol_o_id<:o_id AND ol_o_id>=:o_id-20
              AND s_w_id=:w_id AND s_i_id=ol_i_id AND s_quantity <
         :threshold;*/

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
          Stock stock = find_stock(warehouse_id, line.ol_i_id);
          if (stock.s_quantity < threshold)
          {
            s_i_ids.push_back(line.ol_i_id);
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
      int y = rand() % 100;
      if (y <= 60)
      {
        // 60%: order status by last name
        char c_last[Customer::MAX_LAST + 1];
        tpcc::make_last_name(
          random_int(1, customers_per_district),
          c_last);
        uint32_t w_id = generate_warehouse();
        uint32_t d_id = generate_district();
        order_status(
          w_id, d_id, c_last, &output);
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
        // select in range [1, num_warehouses] excluding w_id
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