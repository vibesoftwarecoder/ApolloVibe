/**
 * @file src/remote_usb/client_authorization.h
 * @brief The answer the tunnel gets when it asks whether a client may forward a device.
 */
#pragma once

#include <cstdint>
#include <string>

namespace remote_usb {

  /** The authorizer's answer for one certificate at one moment. */
  enum class client_authorization : std::uint8_t {
    allowed,
    /** The certificate no longer matches a paired client. */
    not_paired,
    /** The client lacks the USB forwarding permission. */
    forbidden,
    /** A stream session is required and the client has none. */
    no_stream,
  };

  /** The decision plus who the certificate belongs to (the paired client's id), so the
   *  tunnel can cut that client's forwards when the decision later changes. */
  struct authorization_result {
    client_authorization status {client_authorization::not_paired};
    /** Empty when the certificate is not paired. */
    std::string client_id;
  };

}  // namespace remote_usb
