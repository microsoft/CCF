# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Stub definitions for gersemi formatter to recognise custom CCF CMake
# functions. These mirror the cmake_parse_arguments calls in the real
# implementations but contain no logic.

function(add_ccf_app name)
  cmake_parse_arguments(
    PARSE_ARGV 1
    PARSED_ARGS
    ""
    ""
    "SRCS;INCLUDE_DIRS;SYSTEM_INCLUDE_DIRS;LINK_LIBS;DEPS;INSTALL_LIBS"
  )
endfunction()

function(add_ccf_static_library name)
  cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;LINK_LIBS")
endfunction()

function(add_e2e_test)
  cmake_parse_arguments(
    PARSE_ARGV 0
    PARSED_ARGS
    "DETECT_DEADLOCKS"
    "NAME;PYTHON_SCRIPT;LABEL;CURL_CLIENT;BUCKET;TSAN_SUPPRESSIONS"
    "CONSTITUTION;ADDITIONAL_ARGS;BUILD_DEPENDS;CONFIGURATIONS"
  )
endfunction()

function(add_test_target name)
endfunction()

function(add_test_label test)
endfunction()

function(add_picobench name)
  cmake_parse_arguments(
    PARSE_ARGV 1
    PARSED_ARGS
    ""
    ""
    "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )
endfunction()

function(add_test_bin name)
endfunction()

function(add_fuzz_test name)
endfunction()

function(add_unit_test name)
  cmake_parse_arguments(
    PARSE_ARGV 1
    PARSED_ARGS
    "DETECT_DEADLOCKS"
    ""
    "LABELS;CONFIGURATIONS"
  )
endfunction()

function(add_san_test_properties name)
endfunction()

function(add_warning_checks name)
endfunction()

function(add_san name)
endfunction()

function(add_hardening name)
endfunction()

function(add_tidy name)
endfunction()

function(enable_coverage name)
endfunction()

function(ccf_detect_stacktrace)
endfunction()

# Third-party: Corrosion (corrosion-rs/corrosion)
function(corrosion_import_crate)
  cmake_parse_arguments(
    PARSE_ARGV 0
    PARSED_ARGS
    ""
    "MANIFEST_PATH;PROFILE"
    "CRATES;CRATE_TYPES"
  )
endfunction()

function(corrosion_set_env_vars target)
endfunction()
