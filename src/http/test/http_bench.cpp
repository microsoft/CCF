// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/ds/enum_formatter.h"
#include "http/http_builder.h"
#include "http/http_parser.h"

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

// A processor which does nothing but drop the completed message, to avoid the
// benchmark being dominated by the cost of storing parsed requests.
struct NullRequestProcessor : public http::RequestProcessor
{
  size_t count = 0;

  void handle_request(
    llhttp_method,
    const std::string_view&,
    ccf::http::HeaderMap&&,
    std::vector<uint8_t>&&,
    int32_t) override
  {
    ++count;
  }
};

// Build a single valid POST request with a body of the given size.
static std::vector<uint8_t> make_request(size_t body_size)
{
  const std::vector<uint8_t> body(body_size, 'a');
  return http::build_post_request(body);
}

// Parse the same complete, valid request repeatedly. Every request passes
// through the Content-Length check added in headers_complete(), so this
// measures the per-request cost of parsing (including that check) on the
// common, non-rejected path.
template <size_t BodySize>
static void parse_request(picobench::state& s)
{
  const auto req = make_request(BodySize);

  NullRequestProcessor proc;
  ccf::http::ParserConfiguration config;
  // Use a generous limit so that all benchmarked requests are accepted and
  // exercise the full parsing path rather than the early-exit path.
  config.max_body_size = ccf::ds::SizeString("1GB");

  http::RequestParser parser(proc, config);

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    parser.execute(req.data(), req.size());
  }
  s.stop_timer();

  if (proc.count != static_cast<size_t>(s.iterations()))
  {
    throw std::logic_error("Unexpected number of parsed requests");
  }
}

const std::vector<int> iteration_counts = {100, 1000};

PICOBENCH_SUITE("parse_request");
PICOBENCH(parse_request<0>).iterations(iteration_counts).baseline();
PICOBENCH(parse_request<64>).iterations(iteration_counts);
PICOBENCH(parse_request<1024>).iterations(iteration_counts);
PICOBENCH(parse_request<16384>).iterations(iteration_counts);
PICOBENCH(parse_request<65536>).iterations(iteration_counts);
