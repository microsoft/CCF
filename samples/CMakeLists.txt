# Ensure sample apps are built as external apps, with old logging macros unavailable
# remove_definitions(-DCCF_LOGGER_NO_DEPRECATE)

# Add Logging app
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/apps/logging)

# Add Basic app
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/apps/basic)

# Add NoBuiltins app
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/apps/nobuiltins)

# Add Programmability app
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/apps/programmability)

# Add JS generic extension app
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/apps/js_generic_extension)
