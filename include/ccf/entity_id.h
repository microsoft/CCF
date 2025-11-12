// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/kv/serialisers/blit_serialiser.h"

#include <string>

namespace ccf
{
  template <typename FmtExtender = void>
  struct EntityId
  {
  public:
    // The underlying value type should be blit-serialisable so that it can be
    // written to and read from the ring buffer
    static constexpr size_t LENGTH = 64; // hex-encoded SHA-256 hash
    using Value = std::string; // < hex-encoded hash

  private:
    Value id;

  public:
    EntityId() = default;
    EntityId(const EntityId& id_) = default;
    EntityId(const Value& id_) : id(id_) {}
    EntityId(Value&& id_) : id(std::move(id_)) {}
    EntityId(EntityId&& id_) noexcept : id(std::move(id_)) {}
    EntityId& operator=(EntityId&& other) = default;

    operator std::string() const
    {
      return id;
    }

    EntityId& operator=(const EntityId& other)
    {
      if (this != &other)
      {
        id = other.id;
      }
      return *this;
    }

    EntityId& operator=(const Value& id_)
    {
      id = id_;
      return *this;
    }

    bool operator==(const EntityId& other) const
    {
      return id == other.id;
    }

    bool operator!=(const EntityId& other) const
    {
      return !(*this == other);
    }

    bool operator<(const EntityId& other) const
    {
      return id < other.id;
    }

    Value& value()
    {
      return id;
    }

    [[nodiscard]] const Value& value() const
    {
      return id;
    }

    [[nodiscard]] char const* data() const
    {
      return id.data();
    }

    [[nodiscard]] size_t size() const
    {
      return id.size();
    }
  };

  template <typename FmtExtender>
  inline void to_json(nlohmann::json& j, const EntityId<FmtExtender>& entity_id)
  {
    j = entity_id.value();
  }

  template <typename FmtExtender>
  inline void from_json(
    const nlohmann::json& j, EntityId<FmtExtender>& entity_id)
  {
    if (j.is_string())
    {
      entity_id = j.get<std::string>();
    }
    else
    {
      throw ccf::JsonParseError(fmt::format(
        "{} should be hex-encoded string: {}",
        FmtExtender::ID_LABEL,
        j.dump()));
    }
  }

  template <typename FmtExtender>
  inline std::string schema_name(
    [[maybe_unused]] const EntityId<FmtExtender>* entity_id_type)
  {
    return FmtExtender::ID_LABEL;
  }

  template <typename FmtExtender>
  inline void fill_json_schema(
    nlohmann::json& schema,
    [[maybe_unused]] const EntityId<FmtExtender>* entity_id_type)
  {
    schema["type"] = "string";

    // According to the spec, "format is an open value, so you can use any
    // formats, even not those defined by the OpenAPI Specification"
    // https://swagger.io/docs/specification/data-models/data-types/#format
    schema["format"] = "hex";
    schema["pattern"] =
      fmt::format("^[a-f0-9]{{{}}}$", EntityId<FmtExtender>::LENGTH);
  }

  struct MemberIdFormatter
  {
    static std::string format(const std::string& core)
    {
      return fmt::format("m[{}]", core);
    }

    static constexpr auto ID_LABEL = "MemberId";
  };
  using MemberId = EntityId<MemberIdFormatter>;

  struct UserIdFormatter
  {
    static std::string format(const std::string& core)
    {
      return fmt::format("u[{}]", core);
    }

    static constexpr auto ID_LABEL = "UserId";
  };
  using UserId = EntityId<UserIdFormatter>;

  struct NodeIdFormatter
  {
    static std::string format(const std::string& core)
    {
      return fmt::format("n[{}]", core);
    }

    static constexpr auto ID_LABEL = "NodeId";
  };
  using NodeId = EntityId<NodeIdFormatter>;
}

// NOLINTBEGIN(cert-dcl58-cpp)
namespace std
{
  template <typename FmtExtender>
  static inline std::ostream& operator<<(
    std::ostream& os, const ccf::EntityId<FmtExtender>& entity_id)
  {
    if constexpr (std::is_same_v<FmtExtender, void>)
    {
      os << entity_id.value();
    }
    else
    {
      os << FmtExtender::format(entity_id.value());
    }
    return os;
  }

  template <typename FmtExtender>
  struct hash<ccf::EntityId<FmtExtender>>
  {
    size_t operator()(const ccf::EntityId<FmtExtender>& entity_id) const
    {
      return std::hash<std::string>{}(entity_id.value());
    }
  };
}
// NOLINTEND(cert-dcl58-cpp)

FMT_BEGIN_NAMESPACE
template <typename FmtExtender>
struct formatter<ccf::EntityId<FmtExtender>>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::EntityId<FmtExtender>& v, FormatContext& ctx) const
  {
    std::stringstream ss;
    ss << v;
    return format_to(ctx.out(), "{}", ss.str());
  }
};
FMT_END_NAMESPACE

namespace ccf::kv::serialisers
{
  template <typename FmtExtender>
  struct BlitSerialiser<ccf::EntityId<FmtExtender>>
  {
    static SerialisedEntry to_serialised(
      const ccf::EntityId<FmtExtender>& entity_id)
    {
      const auto& data = entity_id.value();
      return SerialisedEntry(data.begin(), data.end());
    }

    static ccf::EntityId<FmtExtender> from_serialised(
      const SerialisedEntry& data)
    {
      return ccf::EntityId<FmtExtender>(std::string(data.begin(), data.end()));
    }
  };
}