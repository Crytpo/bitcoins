cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

# cmake setup
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# general setup
set(NUMBER_OF_GROUPS 66)
set(GROUP_NUMBER "00")


project(its2016 C CXX)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
      "Choose the type of build." FORCE)
endif()

# doygen setup
SET(DOXYGEN_CONFIG_IN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/doc/template.doxy.in")
set(DEFAULT_DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/doc")

include(testing)
include(doxygenSupport)
include(CheckCPUID)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(FindCheck)

# set required C and C++ standard version
if(CMAKE_MAJOR_VERSION EQUAL 2 OR (CMAKE_MAJOR_VERSION EQUAL 3 AND CMAKE_MINOR_VERSION EQUAL 0))
  # let's hope for the best
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
  set(CMAKE_C_STANDARD 11)
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_C_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

# check cpuid
CheckCPUID()

# check compiler flags
foreach(flag IN ITEMS "-Wall" "-fdiagnostics-color=auto")
  check_c_compiler_flag(${flag} CC_SUPPORTS_${flag})
  check_cxx_compiler_flag(${flag} CXX_SUPPORTS_${flag})

  if(CC_SUPPORTS_${flag})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flag}")
  endif()
  if(CXX_SUPPORTS_${flag})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}")
  endif()
endforeach(flag)

find_package(Check REQUIRED)

# add aubdirectories
add_subdirectory(tls)

message(STATUS "---------------------------------------------------------------------")
message(STATUS "Configuration for ${CMAKE_PROJECT_NAME} done.")
message(STATUS "BUILD TYPE:        ${CMAKE_BUILD_TYPE}")
message(STATUS "CC:                ${CMAKE_C_COMPILER}")
message(STATUS "CXX:               ${CMAKE_CXX_COMPILER}")
message(STATUS "CPU supports:")
if(HAVE_CPU_RDTSCP)
  message(STATUS "  RDTSCP")
endif()
message(STATUS "")
message(STATUS "Available targets:")
message(STATUS "  all...............Builds all programs.")
message(STATUS "  suite.............Builds the test program.")
message(STATUS "  check.............Runs the test program.")
message(STATUS "  doxygen...........Build doxygen documentation.")
message(STATUS "---------------------------------------------------------------------")
