#include <array>
#include <nlohmann/json.hpp>
#include <vector>

template <typename TTag, bool Required, typename TTarget>
struct JsonField
{
  static constexpr auto name = TTag::name;
  static constexpr auto required = Required;
  using Target = TTarget;
};

template <size_t N>
auto json_find_fields(
  const nlohmann::json& j,
  const std::array<std::string, N>& fields,
  bool required) -> std::array<nlohmann::json::const_iterator, N>
{
  if (!j.is_object())
  {
    throw std::invalid_argument("Expected an object, received " + j.dump());
  }

  std::array<nlohmann::json::const_iterator, N> found = {};

  for (size_t i = 0; i < fields.size(); ++i)
  {
    const auto& field = fields[i];
    const auto it = j.find(field);
    if (required && it == j.end())
    {
      throw std::invalid_argument(
        "Object is missing required field '" + field +
        "'. Object is: " + j.dump());
    }

    found[i] = it;
  }

  return found;
}

template <typename T>
struct JsonSpec;

struct RecordParams
{
  size_t id;
  std::string msg;
};

template <>
struct JsonSpec<RecordParams>
{
  struct TAG_id
  {
    static constexpr auto name = "id";
  };
  struct MSG_id
  {
    static constexpr auto name = "msg";
  };

  using RequiredFields = std::tuple<
    JsonField<TAG_id, true, size_t>,
    JsonField<MSG_id, true, std::string>>;
};

template <typename T>
void parse_with_validation(const nlohmann::json& j, T& t)
{
  using Spec = JsonSpec<T>;
}

int main(int argc, char** argv)
{
  {
    nlohmann::json a;
    a["hello"] = "world";

    const auto found =
      json_find_fields(a, std::array<std::string, 1>{"hello"}, true);
  }
  return 0;
}

// struct FoundJsonFields
// {
//   std::vector <
// };

// template <typename Target, typename Spec>
// struct JsonValidator
// {
//   void from_json(const nlohmann::json& j)
//   {
//     for (const auto& required_field : Spec::required_fields)
//     {
//     }
//   }
// };
// struct RecordTag
// {
//   static constexpr auto name = "LOG_record";
// };