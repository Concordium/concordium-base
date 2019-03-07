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
set( HEADERS
    include/ed25519.h
    include/ed25519_cryptonite_exts.h
    include/ed25519-donna-64bit-tables.h
    include/ed25519-donna-batchverify.h
    include/ed25519-donna-portable.h
    include/ed25519-donna-32bit-tables.h
    include/ed25519-donna-64bit-x86.h
    include/ed25519-donna-64bit-sse2.h
    include/ed25519-donna-impl-sse2.h
    include/ed25519-donna-impl-base.h
    include/ed25519-donna-32bit-sse2.h
    include/ed25519-donna-64bit-x86-32bit.h
    include/ed25519-donna.h
    include/ed25519-donna-basepoint-table.h
    include/ed25519-donna-portable-identify.h

    include/ed25519-hash.h
    include/ed25519-hash-custom.h
    
    include/ed25519-randombytes.h
    include/ed25519-randombytes-custom.h

    include/curve25519-donna-helpers.h
    include/curve25519-donna-sse2.h
    include/curve25519-donna-32bit.h
    include/curve25519-donna-64bit.h
   
    include/ec_vrf_ed25519-sha256.h
    include/Hacl_SHA2_256.h
    
    include/kremlib_base.h
    include/kremlib.h
   
    include/modm-donna-32bit.h
    include/modm-donna-64bit.h
    
    include/Hacl_SHA2_512.h
    include/hacl_test_utils.h
    
    include/regression.h
    include/test-ticks.h)

add_library( concordium-crypto SHARED ${SRCS} ${HEADERS})

target_compile_definitions( concordium-crypto
    PUBLIC ED25519_CUSTOMHASH=1 ED25519_CUSTOMRANDOM=1)

set_target_properties( concordium-crypto PROPERTIES
    VERSION 0.1
    SOVERSION 0
    PUBLIC_HEADER "${HEADERS}")

install( TARGETS concordium-crypto 
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include/concordium-crypto)

# Unit test
set( TEST_SRCS c-src/test-internals.c)
add_executable( test-internals ${TEST_SRCS})
target_link_libraries( test-internals PUBLIC concordium-crypto)

add_test( NAME test-internals-cpp COMMAND test-internals)
