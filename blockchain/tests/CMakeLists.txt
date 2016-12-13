add_definitions(${CHECK_DEFINITIONS})
include_directories(${CHECK_INCLUDE_DIRS})
link_directories(${CHECK_LIBRARY_DIRS})

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads)

if(CMAKE_USE_PTHREADS_INIT)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

foreach(target IN ITEMS merkletree blockchain)
  add_executable("test_${target}" "${target}.cpp")
  target_link_libraries("test_${target}" bc_primitives ${CHECK_LIBRARIES})

  add_test(NAME ${target} COMMAND "test_${target}")

  add_custom_target("valgrind_test_${target}"
    env CK_FORK=no valgrind ${VALGRIND_ARGUMENTS}
    $<TARGET_FILE:test_${target}>
    DEPENDS test_${target})
endforeach(target)
