/**
 * @file tests/unit/test_usb_forwarding_capability.cpp
 * @brief Test src/nvhttp.cpp, the `GET /api/v1/usb-forwarding` capability reply.
 * @details The MoonlightVibe client parses this body and treats anything outside version 1 as "no host support",
 *          so these tests pin the exact shape. USB forwarding is not implemented yet, so the reply must say
 *          disabled and must carry no port or token.
 */
#include "../tests_common.h"

#include <src/nvhttp.h>

#include <nlohmann/json.hpp>

TEST(UsbForwardingCapability, ReportsDisabledVersionOne) {
  const auto body = nlohmann::json::parse(nvhttp::usb_forwarding_capability_json());

  ASSERT_TRUE(body.is_object());
  ASSERT_TRUE(body.contains("version"));
  EXPECT_EQ(body["version"], 1);
  ASSERT_TRUE(body.contains("enabled"));
  ASSERT_TRUE(body["enabled"].is_boolean());
  EXPECT_FALSE(body["enabled"].get<bool>());
  ASSERT_TRUE(body.contains("available"));
  ASSERT_TRUE(body["available"].is_boolean());
  EXPECT_FALSE(body["available"].get<bool>());
  ASSERT_TRUE(body.contains("reason"));
  EXPECT_EQ(body["reason"], "disabled");
}

TEST(UsbForwardingCapability, NeverHandsOutCredentialsWhenDisabled) {
  const auto body = nlohmann::json::parse(nvhttp::usb_forwarding_capability_json());

  // The client only reads these when available is true, but a disabled host must not send them at all.
  EXPECT_FALSE(body.contains("port"));
  EXPECT_FALSE(body.contains("token"));
}

TEST(UsbForwardingCapability, StaysUnderTheClientsSizeLimit) {
  // The client rejects a body over 4096 bytes.
  EXPECT_LT(nvhttp::usb_forwarding_capability_json().size(), 4096u);
}
