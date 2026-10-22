#if defined(VALIJSON_USE_BOOST_REGEX) && VALIJSON_USE_BOOST_REGEX

#include <boost/regex.hpp>

namespace valijson {
namespace internal {
using boost::regex;
using boost::regex_match;
using boost::regex_search;
using boost::smatch;
} // namespace internal
} // namespace valijson

#else

#include <regex>

namespace valijson {
namespace internal {
using std::regex;
using std::regex_match;
using std::regex_search;
using std::smatch;
} // namespace internal
} // namespace valijson

#endif
