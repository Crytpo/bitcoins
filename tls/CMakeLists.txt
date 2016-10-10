set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads)

if(CMAKE_USE_PTHREADS_INIT)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

set(PRIMITIVES_SOURCES
    ascon/ascon.c
    ascon128.cpp
    counter.cpp
    hmac-sha2.cpp
    prf.cpp
    random.cpp
    sha2.cpp
    tls-ascon.cpp)

add_library(primitives SHARED ${PRIMITIVES_SOURCES})

add_subdirectory(tests)
