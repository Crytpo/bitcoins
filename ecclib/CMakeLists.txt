file(GLOB_RECURSE ECC_LIB_SOURCES
     "bi/*.c"
     "eccp/*.c"
     "gfp/*.c"
     "protocols/*.c"
     "utils/*.c")

add_library(ecc_lib SHARED ${ECC_LIB_SOURCES})
target_include_directories(ecc_lib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
