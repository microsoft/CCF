#pragma once

#include "tpcc_tables.h"
#include "tpcc_common.h"

#include <cinttypes>
#include <vector>
#include <string.h>

namespace tpcc
{
  class TpccTransactions
  {
  private:
    ccf::EndpointContext& args;
    int32_t num_warehouses;
    int32_t districts_per_warehouse;
    int32_t customers_per_district;
    static constexpr int STOCK_LEVEL_ORDERS = 20;
    static constexpr float MIN_PAYMENT_AMOUNT = 1.00;
    static constexpr float MAX_PAYMENT_AMOUNT = 5000.00;

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

    std::optional<OrderLine> find_order_line(int32_t w_id, int32_t d_id, int32_t o_id, int32_t number)
    {
      OrderLine::Key key = {o_id, d_id, w_id, number};
      auto order_lines_table = args.tx.ro(tpcc::TpccTables::order_lines);
      return order_lines_table->get(key);
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
      Customer::Key key = {c_id, d_id, w_id};
      auto customers_table = args.tx.ro(tpcc::TpccTables::customers);
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

    void order_status(
      int32_t warehouse_id,
      int32_t district_id,
      int32_t customer_id,
      OrderStatusOutput* output)
    {
      //~ printf("order status %d %d %d\n", warehouse_id, district_id,
      //customer_id);
      auto customer = find_customer(warehouse_id, district_id, customer_id);
      internal_order_status(
        customer, output);
    }

    Customer find_customer_by_name(int32_t w_id, int32_t d_id, const char* c_last)
    {
      // select (w_id, d_id, *, c_last) order by c_first
      Customer customer_ret;
      auto customers_table = args.tx.ro(tpcc::TpccTables::customers);
      customers_table->foreach([&](const Customer::Key&, const Customer& c) {
        if (c.c_w_id == w_id && c.c_d_id == d_id && strcmp(c.c_last.data(), c_last) == 0)
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
      //~ printf("order status %d %d %s\n", warehouse_id, district_id, c_last);
      Customer customer =
        find_customer_by_name(warehouse_id, district_id, c_last);
      internal_order_status(customer, output);
    }

    Order find_last_order_by_customer(
      const int32_t w_id, const int32_t d_id, const int32_t c_id)
    {
      Order order;

      auto orders_table = args.tx.ro(tpcc::TpccTables::orders);
      orders_table->foreach([&](const Order::Key&, const Order& o) {
        if (o.o_c_id == c_id && o.o_d_id == d_id && o.o_w_id == w_id)
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
        OrderLine line = find_order_line(
          customer.c_w_id, customer.c_d_id, order.o_id, line_number).value();
        output->lines[line_number - 1].ol_i_id = line.ol_i_id;
        output->lines[line_number - 1].ol_supply_w_id = line.ol_supply_w_id;
        output->lines[line_number - 1].ol_quantity = line.ol_quantity;
        output->lines[line_number - 1].ol_amount = line.ol_amount;
        output->lines[line_number - 1].ol_delivery_d = line.ol_delivery_d;
      }
    }

    int32_t generate_warehouse()
    {
      return rand() % num_warehouses;
    }

    int32_t generate_district()
    {
      return rand() % districts_per_warehouse;
    }

    int32_t generate_cid()
    {
      // TODO: fix this
      return 1;
    }

    Order find_order(int32_t w_id, int32_t d_id, int32_t o_id)
    {
      Order::Key key = {o_id, d_id, w_id};
      auto orders_table = args.tx.ro(tpcc::TpccTables::orders);
      auto order = orders_table->get(key);
      return order.value();
    }

    void delivery(
      int32_t warehouse_id,
      int32_t carrier_id,
      std::array<char, DATETIME_SIZE + 1>& now,
      std::vector<DeliveryOrderInfo>* orders)
    {
      //~ printf("delivery %d %d %s\n", warehouse_id, carrier_id, now);
      for (int32_t d_id = 1; d_id <= District::NUM_PER_WAREHOUSE; ++d_id)
      {
        // Find and remove the lowest numbered order for the district
        // TODO: this should be a lower bound rather than an exact match
        NewOrder::Key new_order_key = {warehouse_id, d_id, 1};
        auto new_orders_table = args.tx.ro(tpcc::TpccTables::new_orders);
        auto new_order = new_orders_table->get(new_order_key);
        if (
          !new_order.has_value() || new_order->no_d_id != d_id ||
          new_order->no_w_id != warehouse_id)
        {
          // No orders for this district
          // 2.7.4.2: If this occurs in max(1%, 1) of transactions, report it
          // (???)
          continue;
        }
        int32_t o_id = new_order->no_o_id;

        DeliveryOrderInfo order;
        order.d_id = d_id;
        order.o_id = o_id;
        orders->push_back(order);

        Order o = find_order(warehouse_id, d_id, o_id);
        o.o_carrier_id = carrier_id;

        float total = 0;
        // TODO: Select based on (w_id, d_id, o_id) rather than using ol_number?
        for (int32_t i = 1; i <= o.o_ol_cnt; ++i)
        {
          std::optional<OrderLine> line = find_order_line(warehouse_id, d_id, o_id, i);
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

      History::Key history_key = {h.h_c_id, h.h_c_d_id, h.h_c_w_id, h.h_d_id, h.h_w_id};
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
      //~ printf("payment %d %d %d %d %d %f %s\n", warehouse_id, district_id,
      //c_warehouse_id, c_district_id, customer_id, h_amount, now);
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
      //~ printf("payment %d %d %d %d %s %f %s\n", warehouse_id, district_id,
      //c_warehouse_id, c_district_id, c_last, h_amount, now);
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

  public:
    TpccTransactions(
      ccf::EndpointContext& args_,
      int32_t num_warehouses_,
      int32_t districts_per_warehouse_,
      int32_t customers_per_district_) :
      args(args_),
      num_warehouses(num_warehouses_),
      districts_per_warehouse(districts_per_warehouse_),
      customers_per_district(customers_per_district_)
    {}

    int32_t stock_level(
      int32_t warehouse_id, int32_t district_id, int32_t threshold)
    {
      /* EXEC SQL SELECT d_next_o_id INTO :o_id FROM district
          WHERE d_w_id=:w_id AND d_id=:d_id; */
      //~ printf("stock level %d %d %d\n", warehouse_id, district_id,
      // threshold);
      District d = find_district(warehouse_id, district_id);
      int32_t o_id = d.d_next_o_id;

      /* EXEC SQL SELECT COUNT(DISTINCT (s_i_id)) INTO :stock_count FROM
         order_line, stock WHERE ol_w_id=:w_id AND ol_d_id=:d_id AND
         ol_o_id<:o_id AND ol_o_id>=:o_id-20
              AND s_w_id=:w_id AND s_i_id=ol_i_id AND s_quantity <
         :threshold;*/

      // retrieve up to 300 tuples from order line, using ( [o_id-20, o_id),
      // d_id, w_id, [1, 15])
      //   and for each retrieved tuple, read the corresponding stock tuple
      //   using (ol_i_id, w_id)
      // NOTE: This is a cheat because it hard codes the maximum number of
      // orders. We really should use the ordered b-tree index to find (0,
      // o_id-20, d_id, w_id) then iterate until the end. This will also do
      // less work (wasted finds). Since this is only 4%, it probably doesn't
      // matter much

      // TODO: Test the performance more carefully. I tried: std::set,
      // std::hash_set, std::vector with linear search, and std::vector with
      // binary search using std::lower_bound. The best seemed to be to simply
      // save all the s_i_ids, then sort and eliminate duplicates at the end.
      std::vector<int32_t> s_i_ids;
      // Average size is more like ~30.
      s_i_ids.reserve(300);

      // Iterate over [o_id-20, o_id)
      for (int order_id = o_id - STOCK_LEVEL_ORDERS; order_id < o_id;
           ++order_id)
      {
        // HACK: We shouldn't rely on MAX_OL_CNT. See comment above.
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

      // Filter out duplicate s_i_id: multiple order lines can have the same
      // item
      std::sort(s_i_ids.begin(), s_i_ids.end());
      int num_distinct = 0;
      int32_t last = -1; // NOTE: This relies on -1 being an invalid s_i_id
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
        tpcc::make_last_name(customers_per_district, c_last);
        order_status(
          generate_warehouse(), generate_district(), c_last, &output);
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
      // TODO: set time
      std::array<char, DATETIME_SIZE + 1> now;

      std::vector<DeliveryOrderInfo> orders;
      delivery(generate_warehouse(), carrier, now, &orders);
    }


    void payment() {
    PaymentOutput output;
    int x = random_int(1, 100);
    int y = random_int(1, 100);
    
    int32_t w_id = generate_warehouse();
    int32_t d_id = generate_district();

    int32_t c_w_id;
    int32_t c_d_id;
    if (num_warehouses == 1 || x <= 85) {
        // 85%: paying through own warehouse (or there is only 1 warehouse)
        c_w_id = w_id;
        c_d_id = d_id;
    } else {
        // 15%: paying through another warehouse:
        // select in range [1, num_warehouses] excluding w_id
        c_w_id = random_int_excluding(1, num_warehouses, w_id);
        c_d_id = generate_district();
    }
    float h_amount = random_float(MIN_PAYMENT_AMOUNT, MAX_PAYMENT_AMOUNT);

    // TODO: set time
    std::array<char, DATETIME_SIZE + 1> now;
    if (y <= 60) {
        // 60%: payment by last name
        std::array<char, Customer::MAX_LAST + 1> c_last;
        make_last_name(customers_per_district, c_last.data());
        payment(w_id, d_id, c_w_id, c_d_id, c_last, h_amount, now, &output);
    } else {
        // 40%: payment by id
        payment(w_id, d_id, c_w_id, c_d_id, generate_cid(), h_amount, now, &output);
    }
}
  };
}