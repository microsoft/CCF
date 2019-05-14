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

// template <typename Field, typename... Rest>
// auto json_find_fields(const nlohmann::json& j)
// {
//   const auto it = j.find(Field::name);
//   if (Field::required && it == j.end())
//   {
//     throw std::invalid_argument(
//       "Missing required field '" + Field::name + "' in object: " + j.dump());
//   }

//   if constexpr (sizeof...(Rest) == 0)
//   {
//     return std::make_tuple(it);
//   }
//   else
//   {
//     return std::tuple_cat(it, json_find_fields<Rest...>(j));
//   }
// }

// template <typename T>
// void parse_with_validation(const nlohmann::json& j, T& t)
// {
//   using Spec = JsonSpec<T>;
// }

template <typename T>
struct JsonSpec;

struct RecordParams
{
  size_t id;
  std::string msg;
};

struct TAG_id
{
  static constexpr auto name = "id";
};
struct MSG_id
{
  static constexpr auto name = "msg";
};

#define ADD_JSON_TRANSLATORS(C, attr...) \
  inline void from_json(const nlohmann::json& j, C& c) \
  { \
    _JSON_N(attr)(FROM, attr) \
  } \
  inline void to_json(nlohmann::json& j, const C& c) \
  { \
    _JSON_N(attr)(TO, attr) \
  }

#define DECLARE_REQUIRED_JSON_FIELDS(TYPE, FIELD_A, FIELD_B)
DECLARE_REQUIRED_JSON_FIELDS(RecordParams, id, msg)

enum ErrorCodes : int16_t
{
#define XX(Name, Value) Name = Value,
  XX_ERROR_CODES
#undef XX
};

using FIELD_id = JsonField<TAG_id, true, decltype(RecordParams::id)>;

template <>
struct JsonSpec<RecordParams>
{
  using RequiredFields = std::tuple<
    JsonField<TAG_id, true, size_t>,
    JsonField<MSG_id, true, std::string>>;
};

inline void to_json(nlohmann::json& j, const RecordParams& rp)
{
  j["id"] = rp.id;
  j["msg"] = rp.msg;

  //

  j[FIELD_id::name] = rp.id;
}

inline void from_json(const nlohmann::json& j, RecordParams& rp)
{
  rp.id = j["id"];
  rp.msg = j["msg"];

  //

  const auto it = j.find(FIELD_id::name);
  if (it == j.end())
  {
    throw std::invalid_argument(
      "Missing required field '" + std::string(FIELD_id::name) +
      "' in object: " + j.dump());
  }

  rp.id = it->get<decltype(rp.id)>();
}

int main(int argc, char** argv)
{
  {
    nlohmann::json a;
    a["hello"] = "world";

    // const auto found =
    //   json_find_fields<JsonSpec<RecordParams>::RequiredFields>(a);
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