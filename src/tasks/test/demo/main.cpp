// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "./actions.h"
// #include "./clients.h"
// #include "./node.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

// Writing a bunch of code here, so run a few simple sanity checks that the
// basic operations do what we expect
TEST_CASE("SignAction")
{
  for (size_t i = 0; i < 10; ++i)
  {
    auto orig = std::make_unique<SignAction>();
    auto ser = orig->serialise();

    auto received = deserialise_action(ser);
    auto result = received->do_action();

    orig->verify_serialised_response(result);
  }
}

TEST_CASE("Run" * doctest::skip())
{
  /*
  // Create a node
  Node node(4);

  // Create some clients
  std::vector<Client> clients;
  for (auto i = 0u; i < 12; ++i)
  {
    clients.push_back(node.add_client());
  }

  // Run everything

  // Validate results?
  // Validate clean shutdown?
  // Print some metrics?
  */
}

int main(int argc, char** argv)
{
  // ccf::tasks::TaskSystem::init();
  ccf::logger::config::default_init();

  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}