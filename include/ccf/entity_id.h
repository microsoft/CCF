// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "ds/serialized.h"

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
    EntityId(const Value& id_) : id(id_) {}
    EntityId(Value&& id_) : id(std::move(id_)) {}

    inline operator std::string() const
    {
      return id;
    }

    void operator=(const EntityId& other)
    {
      id = other.id;
    }

    void operator=(const Value& id_)
    {
      id = id_;
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

    std::string trim() const
    {
      // Some entities (typically NodeIds) are printed in many places when
      // VERBOSE_LOGGING is activated so trim them explicitly whenever possible
      // in this case. Otherwise, return the entire value.
#ifdef VERBOSE_LOGGING
      static constexpr size_t entity_id_truncation_max_char_count = 10;
      return id.substr(
        0, std::min(size(), entity_id_truncation_max_char_count));
#else
      return id;
#endif
    }

    Value& value()
    {
      return id;
    }

    const Value& value() const
    {
      return id;
    }

    char const* data() const
    {
      return id.data();
    }

    size_t size() const
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
      throw JsonParseError(
        fmt::format("Entity id should be hex-encoded string: {}", j.dump()));
    }
  }

  template <typename FmtExtender>
  inline std::string schema_name(const EntityId<FmtExtender>&)
  {
    return "EntityId";
  }

  template <typename FmtExtender>
  inline void fill_json_schema(
    nlohmann::json& schema, const EntityId<FmtExtender>&)
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
      return fmt::format("=[{}]=", core);
    }
  };
  using MemberId = EntityId<MemberIdFormatter>;

  struct UserIdFormatter
  {
    static std::string format(const std::string& core)
    {
      return fmt::format("-[{}]-", core);
    }
  };
  using UserId = EntityId<UserIdFormatter>;

  struct NodeIdFormatter
  {
    static std::string format(const std::string& core)
    {
      return fmt::format("<[{}]>", core);
    }
  };
  using NodeId = EntityId<NodeIdFormatter>;
}

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