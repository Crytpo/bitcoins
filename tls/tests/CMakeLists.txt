add_definitions(${CHECK_DEFINITIONS})
include_directories(${CHECK_INCLUDE_DIRS})
link_directories(${CHECK_LIBRARY_DIRS})

add_executable(test_nonce nonce.cpp)
target_link_libraries(test_nonce primitives ${CHECK_LIBRARIES})

add_executable(test_prf prf.cpp)
target_link_libraries(test_prf primitives ${CHECK_LIBRARIES})

add_executable(test_hmac_sha2 hmac_sha2.cpp)
target_link_libraries(test_hmac_sha2
                      primitives ${CHECK_LIBRARIES})

add_executable(test_ascon ascon.cpp)
target_link_libraries(test_ascon primitives ${CHECK_LIBRARIES})

add_executable(test_tls_ascon tls_ascon.cpp)
target_link_libraries(test_tls_ascon primitives ${CHECK_LIBRARIES})

add_executable(test_random random.cpp)
target_link_libraries(test_random primitives ${CHECK_LIBRARIES})

add_test(NAME prf COMMAND test_prf)
add_test(NAME nonce COMMAND test_nonce)
add_test(NAME hmac_sha2 COMMAND test_hmac_sha2)
add_test(NAME ascon COMMAND test_ascon)
add_test(NAME random COMMAND test_random)
foreach(idx RANGE 1 19)
  add_test(NAME "tls_ascon_${idx}" COMMAND test_tls_ascon
    "${CMAKE_CURRENT_SOURCE_DIR}/data/ascon-testcase-${idx}.chal"
    "${CMAKE_CURRENT_SOURCE_DIR}/data/ascon-testcase-${idx}.sol")
endforeach(idx)
