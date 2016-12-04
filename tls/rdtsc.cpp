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

uint64_t rdtsc_clock::begin()
{
  uint32_t cycles_high = 0;
  uint32_t cycles_low = 0;

  // NOTE: many registers in clobbered ops, because otherwise segmentation fault for some reason
  __asm__ __volatile__(
        "cpuid\n\t"               // force previous instructions to be completed
        "rdtsc\n\t"               // read TimeStampCounter (tsc)
        "movl %%edx, %1\n\t"
        "movl %%eax, %0\n\t"
            : "=r" (cycles_low), "=r" (cycles_high)     // output ops
            :                                           // input ops
            : "%rax", "%rbx", "%rcx", "%rdx"            // clobbered ops
  );

  return ( (static_cast<uint64_t>(cycles_high) << 32) | static_cast<uint64_t>(cycles_low));
}

uint64_t rdtsc_clock::end()
{
  uint32_t cycles_high = 0;
  uint32_t cycles_low = 0;
  
  __asm__ __volatile__(
        "rdtscp\n\t"              // read tsc + wait for previous commands
        "movl %%edx, %1\n\t"
        "movl %%eax, %0\n\t"
        "cpuid\n\t"               // force previous instructions to be completed
            : "=r" (cycles_low), "=r" (cycles_high)     // output ops
            :                                           // input ops
            : "%rax", "%rbx", "%rcx", "%rdx"            // clobbered ops
  );
  
  return ( (static_cast<uint64_t>(cycles_high) << 32) | static_cast<uint64_t>(cycles_low));
}
