#include "counter.h"
#include <cstring>

incrementing_nonce::incrementing_nonce(const uint8_t* fixed_common, const uint8_t* fixed_distinct)
{
  // \todo Intialize with given fixed common and fixed distinct part.
}

incrementing_nonce& incrementing_nonce::operator++()
{
  // \todo Increment the counter.

  return *this;
}

void incrementing_nonce::reset(const uint8_t* fixed_distinct)
{
  /// \todo reset counter and fixed distinct part
}

const std::array<uint8_t, incrementing_nonce::nonce_size>& incrementing_nonce::nonce() const
{
  /// \todo return current nonce
}

const std::array<uint8_t, incrementing_nonce::explicit_size>&
incrementing_nonce::explicit_nonce() const
{
  /// \todo return current explicit part of the nonce
}

const std::array<uint8_t, incrementing_nonce::implicit_size>&
incrementing_nonce::implicit_nonce() const
{
  /// \todo return current implicit part of the nonce
}
