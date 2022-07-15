# Ensure sample apps are built as external apps, with old logging macros unavailable
remove_definitions(-DCCF_LOGGER_NO_DEPRECATE)

# Add Logging app
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/apps/logging)

# Add NoBuiltins app
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/apps/nobuiltins)
