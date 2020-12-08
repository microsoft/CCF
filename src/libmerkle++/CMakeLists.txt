project(merkle++ LANGUAGES CXX)

cmake_minimum_required(VERSION 3.18.2)
set(CMAKE_CXX_STANDARD 17)

set(MERKLE++_DIR ${CMAKE_CURRENT_SOURCE_DIR})

option(PROFILE "enable profiling" OFF)
option(EVERCRYPT "enable comparison with EverCrypt Merkle trees" OFF)

enable_testing()
add_subdirectory(test)