set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads)

if(CMAKE_USE_PTHREADS_INIT)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

set(PRIMITIVES_SOURCES
    aes128-cbc.cpp
    aes128.cpp
    ascon/ascon.c
    ascon128.cpp
    const-memcmp.cpp
    counter.cpp
    hmac-sha1.cpp
    hmac-sha2.cpp
    prf.cpp
    random.cpp
    sha1.cpp
    sha2.cpp
    tls-aes-cbc-hmac-sha1.cpp
    tls-ascon.cpp)

add_library(primitives SHARED ${PRIMITIVES_SOURCES})
add_library(clocks SHARED rdtsc.cpp)
add_library(oracles SHARED oracle.cpp remote-oracle.cpp)

add_executable(lucky13 lucky13.cpp attack.cpp)
target_link_libraries(lucky13
                      oracles
                      primitives
                      clocks
                      ${CMAKE_THREAD_LIBS_INIT})

add_executable(mqlucky13 mqlucky13.cpp attack.cpp)
target_link_libraries(mqlucky13
                      oracles
                      primitives
                      clocks
                      ${CMAKE_THREAD_LIBS_INIT})

file(GLOB local_challenges "challenges/its2016g${GROUP_NUMBER}*.chal")
file(GLOB remote_challenges "challenges/its2016g${GROUP_NUMBER}*.rchal")

add_custom_target(tls_local_tsc)
add_custom_target(tls_remote)

foreach(challenge IN LISTS local_challenges)
  get_filename_component(basename "${challenge}" NAME_WE)
  add_custom_target("tls_${basename}_local_tsc"
    $<TARGET_FILE:lucky13>
    attack_local_tsc
    ${challenge}
    ${challenge}.tsc.sol
    DEPENDS lucky13)
  add_dependencies(tls_local_tsc "tls_${basename}_local_tsc")
endforeach(challenge)

foreach(challenge IN LISTS remote_challenges)
  get_filename_component(basename "${challenge}" NAME_WE)
  add_custom_target("tls_${basename}_remote"
    $<TARGET_FILE:mqlucky13>
    ${challenge}
    ${challenge}.sol
    DEPENDS mqlucky13)
  add_dependencies(tls_remote "tls_${basename}_remote")
endforeach(challenge)

add_custom_target(tls DEPENDS tls_remote tls_local_tsc)

set(mqoracle_target "mqoracle.x86_64")
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/${mqoracle_target}
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(tests)
