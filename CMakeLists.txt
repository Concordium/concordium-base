cmake_minimum_required( VERSION 3.0)

project( concordium-crypto)
enable_testing()
include_directories( ${CMAKE_SOURCE_DIR}/include)

# Concordium-crypto Library
set( SRCS
    c-src/ec_vrf_ed25519-sha256.c
    c-src/ed25519.c
    c-src/Hacl_SHA2_256.c
    c-src/Hacl_SHA2_512.c
    c-src/hacl_test_utils.c
    c-src/kremlib.c)

add_library( concordium-crypto SHARED ${SRCS})

set_target_properties( concordium-crypto
    PROPERTIES
    VERSION 0.1
    SOVERSION 0) 

# Unit test
set( TEST_SRCS c-src/test-internals.c)
add_executable( test-internals ${TEST_SRCS})
target_link_libraries( test-internals PUBLIC concordium-crypto)

add_test( NAME test-internals-cpp COMMAND test-internals)
