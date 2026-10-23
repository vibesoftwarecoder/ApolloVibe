/** @file src/remote_usb/usbip_endpoint.h
 *  @brief Value-only endpoint shared by local USB/IP consumers.
 *
 *  Derived from AlkaidLab/foundation-sunshine (GPL-3.0).
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace remote_usb {

struct endpoint {
  std::string address { "127.0.0.1" };
  std::uint16_t port { 0 };
  std::string busid;

  friend bool operator==(const endpoint &, const endpoint &) = default;
};

/**
 * Bus id as the Moonlight client sends it: 1 to 31 bytes of [0-9A-Za-z.:-].
 * This is the wire-level check only; anything that reaches a process command
 * line must also pass valid_usbip_busid_shape().
 */
inline bool valid_busid_charset(std::string_view busid) noexcept {
  if (busid.empty() || busid.size() > 31) {
    return false;
  }
  for (const char c : busid) {
    const bool allowed = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                         (c >= 'A' && c <= 'Z') || c == '-' || c == '.' || c == ':';
    if (!allowed) {
      return false;
    }
  }
  return true;
}

/**
 * The numeric shape of a real USB bus id: ^[1-9][0-9]*-[1-9][0-9]*(\.[0-9]+)*$
 * ("1-2", "3-14", "1-2.4" for a device behind a hub).  It cannot start with a
 * dash, so a bus id can never be read as an option by usbip.exe.
 */
inline bool valid_usbip_busid_shape(std::string_view busid) noexcept {
  if (!valid_busid_charset(busid)) {
    return false;
  }
  std::size_t i = 0;
  const auto digits = [&](bool nonzero_first) {
    const std::size_t start = i;
    while (i < busid.size() && busid[i] >= '0' && busid[i] <= '9') {
      ++i;
    }
    if (i == start) {
      return false;
    }
    return !nonzero_first || busid[start] != '0';
  };
  if (!digits(true) || i >= busid.size() || busid[i] != '-') {
    return false;
  }
  ++i;
  if (!digits(true)) {
    return false;
  }
  while (i < busid.size()) {
    if (busid[i] != '.') {
      return false;
    }
    ++i;
    if (!digits(false)) {
      return false;
    }
  }
  return true;
}

}  // namespace remote_usb
