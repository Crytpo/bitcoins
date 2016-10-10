#include <cpuid.h>
#include <stdint.h>

#define bit_RDTSCP (1 << 27)

int main()
{
  uint32_t eax, ebx, ecx, edx;
  /* call cpuid to check if RDTSCP instructions are available */
  if (__get_cpuid(0x80000001, &eax, &ebx, &ecx, &edx))
  {
    if (edx & bit_RDTSCP)
    {
      return 0;
    }
  }

  return 1;
}
