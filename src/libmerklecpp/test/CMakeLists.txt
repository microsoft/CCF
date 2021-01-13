set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

function(add_merklecpp_test target source)
  add_unit_test(${MERKLECPP_TEST_PREFIX}${target} ${source})
  set_tests_properties(${MERKLECPP_TEST_PREFIX}${target} PROPERTIES LABELS "merklecpp")
endfunction()

add_merklecpp_test(demo_tree demo_tree.cpp)
add_merklecpp_test(time_large_trees time_large_trees.cpp)
add_merklecpp_test(paths paths.cpp)
add_merklecpp_test(flush flush.cpp)
add_merklecpp_test(retract retract.cpp)
add_merklecpp_test(past_root past_root.cpp)
add_merklecpp_test(past_paths past_paths.cpp)
add_merklecpp_test(serialisation serialisation.cpp)
add_merklecpp_test(
  partial_serialisation partial_serialisation.cpp
)

if(TARGET evercrypt.host)
  add_merklecpp_test(compare_evercrypt compare_evercrypt.cpp)
endif()

if(OPENSSL
   OR MBEDTLS
   OR EVERCRYPT
)
  add_merklecpp_test(
    compare_hash_functions compare_hash_functions.cpp
  )
endif()