cmake_minimum_required(VERSION 3.12)
project(t_cose
    DESCRIPTION "t_cose"
    LANGUAGES C
    VERSION 1.0.1)

# Constants
set(CRYPTO_PROVIDERS "OpenSSL" "MbedTLS" "Test")

# Project options
set(CRYPTO_PROVIDER "OpenSSL" CACHE STRING "The crypto provider to use: ${CRYPTO_PROVIDERS}")
set(BUILD_TESTS ON CACHE BOOL "Build tests")
set(BUILD_EXAMPLES ON CACHE BOOL "Build examples")

if (NOT CRYPTO_PROVIDER IN_LIST CRYPTO_PROVIDERS)
    message(FATAL_ERROR "CRYPTO_PROVIDER must be one of ${CRYPTO_PROVIDERS}")
endif()

# Built-in CMake options
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Create shared instead of static libraries")

# Used in find_package() calls as preferred search paths
set(QCBOR_ROOT "" CACHE PATH "Installation prefix of QCBOR")
set(MbedTLS_ROOT "" CACHE PATH "Installation prefix of MbedTLS")
set(OpenSSL_ROOT "" CACHE PATH "Installation prefix of OpenSSL")

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "No build type selected, defaulting to Release")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

if(CRYPTO_PROVIDER STREQUAL "MbedTLS")

    find_package(MbedTLS REQUIRED)
    set(CRYPTO_LIBRARY MbedTLS::MbedCrypto)
    set(CRYPTO_COMPILE_DEFS -DT_COSE_USE_PSA_CRYPTO=1)
    set(CRYPTO_ADAPTER_SRC crypto_adapters/t_cose_psa_crypto.c)

elseif(CRYPTO_PROVIDER STREQUAL "OpenSSL")

    find_package(OpenSSL REQUIRED)
    set(CRYPTO_LIBRARY OpenSSL::Crypto)
    set(CRYPTO_COMPILE_DEFS -DT_COSE_USE_OPENSSL_CRYPTO=1)
    set(CRYPTO_ADAPTER_SRC crypto_adapters/t_cose_openssl_crypto.c)

elseif(CRYPTO_PROVIDER STREQUAL "Test")

    add_library(b_con_hash crypto_adapters/b_con_hash/sha256.c)
    target_include_directories(b_con_hash PUBLIC crypto_adapters/b_con_hash)

    set(CRYPTO_LIBRARY b_con_hash)
    set(CRYPTO_COMPILE_DEFS -DT_COSE_USE_B_CON_SHA256 -DT_COSE_ENABLE_HASH_FAIL_TEST)
    set(CRYPTO_ADAPTER_SRC crypto_adapters/t_cose_test_crypto.c)

else()
    message(FATAL_ERROR "Bug!")
endif()

# Global compile options applying to all targets
add_compile_options(-pedantic -Wall)

set(T_COSE_SRC_COMMON
    src/t_cose_sign1_sign.c
    src/t_cose_parameters.c
    src/t_cose_sign1_verify.c
    src/t_cose_util.c
    src/t_cose_short_circuit.c
)

find_package(QCBOR REQUIRED)

add_library(t_cose ${T_COSE_SRC_COMMON} ${CRYPTO_ADAPTER_SRC})
target_compile_options(t_cose PRIVATE -ffunction-sections)
target_compile_definitions(t_cose PRIVATE ${CRYPTO_COMPILE_DEFS})
target_include_directories(t_cose PUBLIC inc PRIVATE src)
target_link_libraries(t_cose PUBLIC QCBOR::QCBOR PRIVATE ${CRYPTO_LIBRARY})

include(GNUInstallDirs)

install(TARGETS t_cose
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY inc/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if (BUILD_EXAMPLES)

    if (CRYPTO_PROVIDER STREQUAL "MbedTLS")
        add_executable(t_cose_basic_example_psa examples/t_cose_basic_example_psa.c)
        target_link_libraries(t_cose_basic_example_psa PRIVATE t_cose ${CRYPTO_LIBRARY})
    elseif (CRYPTO_PROVIDER STREQUAL "OpenSSL")
        add_executable(t_cose_basic_example_ossl examples/t_cose_basic_example_ossl.c)
        target_link_libraries(t_cose_basic_example_ossl PRIVATE t_cose ${CRYPTO_LIBRARY})
    endif()

endif()

if (BUILD_TESTS)

    enable_testing()

    set(TEST_SRC_COMMON
        main.c
        test/run_tests.c
        test/t_cose_make_test_messages.c
        test/t_cose_test.c
    )

    if (NOT CRYPTO_PROVIDER STREQUAL "Test")
        list(APPEND TEST_SRC_COMMON test/t_cose_sign_verify_test.c)
    endif()

    if (CRYPTO_PROVIDER STREQUAL "MbedTLS")
        set(TEST_SRC_EXTRA test/t_cose_make_psa_test_key.c)
        set(TEST_EXTRA_DEFS)
    elseif(CRYPTO_PROVIDER STREQUAL "OpenSSL")
        set(TEST_SRC_EXTRA test/t_cose_make_openssl_test_key.c)
        set(TEST_EXTRA_DEFS)
    elseif(CRYPTO_PROVIDER STREQUAL "Test")
        set(TEST_SRC_EXTRA)
        set(TEST_EXTRA_DEFS -DT_COSE_ENABLE_HASH_FAIL_TEST -DT_COSE_DISABLE_SIGN_VERIFY_TESTS)
    else()
        message(FATAL_ERROR "Bug!")
    endif()

    add_executable(t_cose_test ${TEST_SRC_COMMON} ${TEST_SRC_EXTRA})
    target_include_directories(t_cose_test PRIVATE src test)
    target_link_libraries(t_cose_test PRIVATE t_cose ${CRYPTO_LIBRARY})
    # Crypto defs are needed because the tests include headers from src/
    target_compile_definitions(t_cose_test PRIVATE ${CRYPTO_COMPILE_DEFS} ${TEST_EXTRA_DEFS})
    
    add_test(NAME t_cose_test COMMAND t_cose_test)

endif()
