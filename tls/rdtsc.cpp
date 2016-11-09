/******************************************************************************
**
** Copyright (C) 2016 Graz University of Technology
**
** Contact: itsec-team@iaik.tugraz.at
**
** IT-SECURITY LICENSE
** Version 1.2, 1st of October 2016
**
** This framework may only be used within the IT-Security exercises 2016. Only
** students that are formally registered within TUGRAZ-online may use it until
** 30th of June 2016. After that date, licensees have the duty to safely
** delete the software framework.
**
** This license does not grant you any rights to re-distribute the software,
** to change the license, to grant access to other individuals, and to
** commercially use the software.
**
** This software is distributed WITHOUT ANY WARRANTY; without even the implied
** warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
**
** If you are interested in a more reasonable license, please use the contact
** information above.
**
******************************************************************************/

#include <iostream>
#include "clocks.h"

using namespace std;


bool checkCpuId()
{
  uint32_t reg[4]; // "GenuineIntel", must be written which can do an intel cpu.
  __asm__ __volatile__(
                       "cpuid" // is a serializing call
                       : "=a"(reg[3]), "=b"(reg[0]), "=c"(reg[2]), "=d"(reg[1])
                       : "a"(0)
                       : "cc"
                       );

  if ((char*)reg != (char*)"GenuineIntel")
  {
    cout << reg << endl;
    cout << "Error: cpu does not provide timestampcounter!" << endl;
    
    return false;
  }
  
  return true;
}

uint64_t rdtsc_clock::begin()
{
  /// \todo Implement start of RDTSC based measurement here.
  // https://www.ccsl.carleton.ca/~jamuir/rdtscpm1.pdf
  // https://www.lmax.com/blog/staff-blogs/2015/10/25/time-stamp-counters/
  // http://stackoverflow.com/questions/12631856/difference-between-rdtscp-rdtsc-memory-and-cpuid-rdtsc
  uint32_t hi = 0;
  uint32_t lo = 0;
  
  if( not checkCpuId())
    return 0;
  
  __asm__ __volatile__(
                       "rdtsc" // waits until previous instructions have been executed
                       : "=a"(lo), "=d"(hi) 
                      );

  return ( ((uint64_t) lo) | (((uint64_t) hi) << 32) );
}

uint64_t rdtsc_clock::end()
{
  /// \todo Implement end of RDTSC based measurement here.
  // https://github.com/prashrock/C/blob/master/micro_benchmarks/rdtsc.c
  uint32_t hi = 0;
  uint32_t lo = 0;
  
  __asm__ __volatile__(
                       "rdtscp"
                       : "=a"(lo), "=d"(hi)
                      );
  
  if (not checkCpuId())
    return 0;
  
  return ( ((uint64_t) lo) | (((uint64_t) hi) << 32) );
}
