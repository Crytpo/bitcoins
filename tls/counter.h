#ifndef COUNTER_H
#define COUNTER_H

#include <array>
#include <cstdint>

// A partially implicit nonce [RFC 5116, §3.2]
//
// When viewing the contents of this struct as an 128 bit integer in network
// byte error (i.e big endian), this should be an incrementing counter with
// fixed high bits.
class incrementing_nonce
{
public:
  static constexpr std::size_t fixed_common_size   = 4;
  static constexpr std::size_t fixed_distinct_size = 4;
  static constexpr std::size_t fixed_size          = fixed_common_size + fixed_distinct_size;
  static constexpr std::size_t counter_size        = 8;
  static constexpr std::size_t implicit_size       = fixed_common_size;
  static constexpr std::size_t explicit_size       = fixed_distinct_size + counter_size;
  static constexpr std::size_t nonce_size          = counter_size + fixed_size;

private:
  static_assert(nonce_size == 16, "nonce needs to consist of 16 bytes");

public:
  /// Initialize with given fixed common and fixed distinc part.
  incrementing_nonce(const uint8_t* fixed_common, const uint8_t* fixed_distinct = nullptr);

  /// Increment the counter.
  incrementing_nonce& operator++();

  /// Reset to a new fixed disctinct value and reset counter to 0.
  void reset(const uint8_t* fixed_distinct);

  /// Return the current nonce.
  const std::array<uint8_t, nonce_size>& nonce() const;
  /// Return the explicit part of the current nonce.
  const std::array<uint8_t, explicit_size>& explicit_nonce() const;
  /// Return the implicit part of the current nonce.
  const std::array<uint8_t, implicit_size>& implicit_nonce() const;
};

#endif
