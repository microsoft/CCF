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
    static const int STOCK_LEVEL_ORDERS = 20;

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
  };
}