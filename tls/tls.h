#ifndef TLS_H
#define TLS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

/// TLS version constants
enum version_constants : uint8_t
{
  TLSv1_2_MAJOR = 3,
  TLSv1_2_MINOR = 3
};

/// TLS content type constants
enum content_type : uint8_t
{
  TLS_APPLICATION_DATA = 23
};

/// The protocol version.
struct protocol_version
{
  /// Major protocol version.
  uint8_t major;
  /// Minor protocol version.
  uint8_t minor;
} __attribute__((packed));

/// The header of the record layer consisting of type, version and length.
struct record_layer_header
{
  /// Record type
  uint8_t type;
  /// Protocol version
  protocol_version version;
  /// Size of the transmitted payload, e.g. the size of the IV plus the size of
  /// the cipher text.
  uint16_t length;
} __attribute__((packed));

#endif
