/**
 * @file src/remote_usb/forward_info.h
 * @brief What the host can say about one running USB forward.
 */
#pragma once

#include <cstdint>
#include <string>

namespace remote_usb {

  /** One authorized forward (being set up or running). Never carries a token or a certificate. */
  struct forward_info {
    /** The paired client's uuid. */
    std::string client_id;
    /** The client-side bus id being forwarded, for example "1-2". */
    std::string busid;
    /** When the forward was authorized, seconds since the Unix epoch. */
    std::int64_t since_unix {0};
  };

}  // namespace remote_usb
