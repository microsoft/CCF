set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_unit_test(${MERKLECPP_TEST_PREFIX}demo_tree demo_tree.cpp)
add_unit_test(${MERKLECPP_TEST_PREFIX}time_large_trees time_large_trees.cpp)
add_unit_test(${MERKLECPP_TEST_PREFIX}paths paths.cpp)
add_unit_test(${MERKLECPP_TEST_PREFIX}flush flush.cpp)
add_unit_test(${MERKLECPP_TEST_PREFIX}retract retract.cpp)
add_unit_test(${MERKLECPP_TEST_PREFIX}past_root past_root.cpp)
add_unit_test(${MERKLECPP_TEST_PREFIX}past_paths past_paths.cpp)
add_unit_test(${MERKLECPP_TEST_PREFIX}serialisation serialisation.cpp)
add_unit_test(
  ${MERKLECPP_TEST_PREFIX}partial_serialisation partial_serialisation.cpp
)

if(TARGET evercrypt.host)
  add_unit_test(${MERKLECPP_TEST_PREFIX}compare_evercrypt compare_evercrypt.cpp)
endif()

if(OPENSSL
   OR MBEDTLS
   OR EVERCRYPT
)
  add_unit_test(
    ${MERKLECPP_TEST_PREFIX}compare_hash_functions compare_hash_functions.cpp
  )
endif()
