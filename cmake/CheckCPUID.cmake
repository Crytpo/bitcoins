set(DIR_OF_THIS ${CMAKE_CURRENT_LIST_DIR})

macro(CheckCPUID)

try_run(CPUID_RDTSCP_FLAG CPUID_COMPILE_RESULT
        ${CMAKE_BINARY_DIR}
        ${DIR_OF_THIS}/check-rdtscp.c)
if(${CPUID_COMPILE_RESULT} AND ${CPUID_RDTSCP_FLAG} EQUAL 0)
  set(HAVE_CPU_RDTSCP true CACHE BOOL "RDTSCP instruction available on host.")
else()
  set(HAVE_CPU_RDTSCP false CACHE BOOL "RDTSCP instruction available on host.")
endif()

mark_as_advanced(HAVE_CPU_RDTSCP)

endmacro(CheckCPUID)
