#include "counter.h"
#include <cstring>

incrementing_nonce::incrementing_nonce(const uint8_t* fixed_common,
    const uint8_t* fixed_distinct)
{
  // create new nonce with fixed data and counter starting at 0
  current_nonce_.fill(0); // set everything to 0 (including counter)

  if (fixed_common != NULL)
  {
    std::copy(&fixed_common[0], &fixed_common[0] + fixed_common_size,
        current_nonce_.data());
  }

  if (fixed_distinct != NULL)
  {
    std::copy(&fixed_distinct[0], &fixed_distinct[0] + fixed_distinct_size,
        current_nonce_.data() + fixed_common_size);
  }
}

incrementing_nonce& incrementing_nonce::operator++()
{
  // extract counter (last counter_size bytes)
  std::array<uint8_t, counter_size> counter;
  std::copy(current_nonce_.begin() + fixed_size, current_nonce_.end(),
      counter.begin());

  // increment counter (in big endian format)
  // if current byte 0xFF -> set to 0 and increment previous byte until no overflow
  for (size_t index = counter_size - 1; index >= 0; --index)
  {
    if (counter[index] < UINT8_MAX)
    {
      counter[index]++;
      break;
    }

    counter[index] = 0;
  }

  // write counter back to nonce
  std::copy(counter.begin(), counter.end(),
      current_nonce_.begin() + fixed_size);

  return *this;
}

void incrementing_nonce::reset(const uint8_t* fixed_distinct)
{
  // set fixed distinct part
  std::copy(&fixed_distinct[0], &fixed_distinct[0] + fixed_common_size,
      current_nonce_.data() + fixed_common_size);

  // set counter to 0
  std::fill(current_nonce_.begin() + fixed_size, current_nonce_.end(), 0);
}

const std::array<uint8_t, incrementing_nonce::nonce_size>& incrementing_nonce::nonce() const
{
  // return current nonce
  return current_nonce_;
}

const std::array<uint8_t, incrementing_nonce::explicit_size>&
incrementing_nonce::explicit_nonce() const
{
  // return explicit part (= fixed distinct + counter) of current nonce
  static std::array<uint8_t, explicit_size> explicit_part; // due to reference!
  std::copy(current_nonce_.begin() + fixed_common_size, current_nonce_.end(),
      explicit_part.begin());

  return explicit_part;
}

const std::array<uint8_t, incrementing_nonce::implicit_size>&
incrementing_nonce::implicit_nonce() const
{
  // return implicit part (= fixed common) of current nonce
  static std::array<uint8_t, implicit_size> implicit_part; // due to reference!
  std::copy(current_nonce_.begin(), current_nonce_.begin() + fixed_common_size,
      implicit_part.begin());

  return implicit_part;
}
