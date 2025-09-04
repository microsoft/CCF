// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <array>
#include <format>
#include <future>
#include <iostream>
#include <memory>
#include <optional>
#include <ranges>
#include <stack>
#include <string>
#include <vector>

// NB: Not currently built, just a sketch of using variants + promise types to
// report a (potentially cancelled or erroring) async result

struct Cancelled
{
  std::string reason;
};

struct TimedOut
{};

struct Actual
{
  size_t x;
  std::string s;
};

template <typename T>
using TResult = std::variant<T, Cancelled, TimedOut>;

using Result = TResult<Actual>;

void do_it(std::promise<Result>& result)
{
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  auto choice = rand() % 4;
  if (choice == 0)
  {
    std::cout << "do_it producing a real value" << std::endl;
    result.set_value(Actual{.x = 42, .s = "hello world"});
  }
  else if (choice == 1)
  {
    std::cout << "do_it simulating a cancellation" << std::endl;
    result.set_value(Cancelled{.reason = "Dumb luck"});
  }
  else if (choice == 2)
  {
    std::cout << "do_it simulating a timeout" << std::endl;
    result.set_value(TimedOut{});
  }
  else if (choice == 3)
  {
    std::cout << "do_it simulating an exception" << std::endl;
    result.set_exception(
      std::make_exception_ptr(std::logic_error("I blew up")));
  }
}

int main()
{
  for (auto i = 0; i < 10; ++i)
  {
    std::cout << "Iteration " << i << std::endl;
    std::promise<Result> result;

    std::future<Result> future = result.get_future();

    std::thread t(do_it, std::ref(result));

    try
    {
      std::cout << "About to call future.get()" << std::endl;
      auto r = future.get();
      std::visit(
        [](auto&& arg) {
          using T = std::decay_t<decltype(arg)>;
          if constexpr (std::is_same_v<T, Actual>)
          {
            std::cout << "  Result is an actual value, with x = " << arg.x
                      << " and s = " << arg.s << std::endl;
          }
          else if constexpr (std::is_same_v<T, Cancelled>)
          {
            std::cout << "  Operation was cancelled, because: " << arg.reason
                      << std::endl;
          }
          else if constexpr (std::is_same_v<T, TimedOut>)
          {
            std::cout << "  Operation timed out" << std::endl;
          }
          else
          {
            static_assert(false, "Non-exhaustive visitor!");
          }
        },
        r);
    }
    catch (const std::exception& e)
    {
      std::cout << "  Exception thrown: " << e.what() << std::endl;
    }

    t.join();
  }
}
