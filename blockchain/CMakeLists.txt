set(BC_PRIMITIVES_SOURCES
    ecclib-glue.cpp
    ecdsa.cpp
    merkletree.cpp
    io.cpp)

set(BC_SOURCES
    blockchain.cpp
    attack.cpp
    main.cpp)

add_library(bc_primitives SHARED ${BC_PRIMITIVES_SOURCES})
target_link_libraries(bc_primitives
                      primitives
                      ecc_lib)

add_executable(blockchain ${BC_SOURCES})
target_link_libraries(blockchain
                      bc_primitives
                      primitives
                      ecc_lib)

add_custom_target("unpack_blockchain"
                  unxz -k -q -f blockchain.xz
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/challenges
                  COMMENT Unpacking blockchain)

add_custom_target("blockchain_generate_attacker_key"
    $<TARGET_FILE:blockchain>
    generate_key
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/attacker-g${GROUP_NUMBER}.pub.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/attacker-g${GROUP_NUMBER}.priv.sol
    DEPENDS blockchain)

add_custom_target("blockchain_attack"
    $<TARGET_FILE:blockchain>
    attack
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/target-g${GROUP_NUMBER}.pub.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/target-g${GROUP_NUMBER}.priv.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/attacker-g${GROUP_NUMBER}.pub.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/attacker-g${GROUP_NUMBER}.priv.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain-g${GROUP_NUMBER}.sol
    DEPENDS blockchain unpack_blockchain)

add_custom_target("valgrind_blockchain_attack"
    valgrind ${VALGRIND_ARGUMENTS}
    $<TARGET_FILE:blockchain>
    attack
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/target-g${GROUP_NUMBER}.pub.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/target-g${GROUP_NUMBER}.priv.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/attacker-g${GROUP_NUMBER}.pub.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/attacker-g${GROUP_NUMBER}.priv.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain-g${GROUP_NUMBER}.sol
    DEPENDS blockchain unpack_blockchain)

add_custom_target("blockchain_verify"
    $<TARGET_FILE:blockchain>
    verify_solution
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/target-g${GROUP_NUMBER}.pub.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/attacker-g${GROUP_NUMBER}.pub.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain-g${GROUP_NUMBER}.sol
    DEPENDS blockchain unpack_blockchain)

add_custom_target("valgrind_blockchain_verify"
    valgrind ${VALGRIND_ARGUMENTS}
    $<TARGET_FILE:blockchain>
    verify_solution
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/target-g${GROUP_NUMBER}.pub.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/attacker-g${GROUP_NUMBER}.pub.sol
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain-g${GROUP_NUMBER}.sol
    DEPENDS blockchain unpack_blockchain)

add_subdirectory(tests)
