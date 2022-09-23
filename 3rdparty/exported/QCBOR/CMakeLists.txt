cmake_minimum_required(VERSION 3.10.2)
project(qcbor
	DESCRIPTION "QCBOR"
	LANGUAGES C
	VERSION 1.0.0)

set(CMAKE_C_FLAGS "-pedantic -Wall -O3 -ffunction-sections")

set(SOURCE
	src/ieee754.c
	src/qcbor_decode.c
	src/qcbor_encode.c
	src/qcbor_err_to_str.c
	src/UsefulBuf.c
) 

add_library(qcbor ${SOURCE})

target_include_directories(qcbor PUBLIC inc)
