set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(evercrypt)
get_target_property(EINC evercrypt INCLUDE_DIRECTORIES)

function(add_merkle_test NAME SRC)
  add_executable(${NAME} ${SRC})
  target_include_directories(${NAME} PRIVATE ${MERKLE++_DIR})
  target_link_libraries(${NAME} evercrypt)
  target_include_directories(${NAME} PRIVATE ${EINC})

  target_compile_definitions(${NAME} PRIVATE HAVE_INSTRUMENTED_EVERCRYPT)

  if (PROFILE)
    target_compile_options(${NAME} PRIVATE -g -pg)
    target_link_options(${NAME} PRIVATE -g -pg)
  endif()

  if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(${NAME} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(${NAME} PRIVATE -fsanitize=address)
  endif()

  add_test(${NAME} ${NAME})
endfunction()

add_merkle_test(demo_tree demo_tree.cpp)
add_merkle_test(compare_evercrypt compare_evercrypt.cpp)
add_merkle_test(time_large_trees time_large_trees.cpp)
add_merkle_test(paths paths.cpp)
add_merkle_test(flush flush.cpp)
add_merkle_test(retract retract.cpp)
add_merkle_test(hashes hashes.cpp)
