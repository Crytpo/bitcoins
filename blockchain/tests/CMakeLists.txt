add_definitions(${CHECK_DEFINITIONS})
include_directories(${CHECK_INCLUDE_DIRS})
link_directories(${CHECK_LIBRARY_DIRS})

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads)

if(CMAKE_USE_PTHREADS_INIT)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

add_executable(test_merkletree merkletree.cpp)
target_link_libraries(test_merkletree bc_primitives ${CHECK_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT})

add_test(NAME merkletree COMMAND test_merkletree)

add_custom_target("valgrind_test_merkletree"
  env CK_FORK=no valgrind ${VALGRIND_ARGUMENTS}
  $<TARGET_FILE:test_merkletree>
  DEPENDS test_merkletree)
