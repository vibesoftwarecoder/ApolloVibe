/**
 * @file tests/unit/test_usb_forwarding_capability.cpp
 * @brief Test src/nvhttp.cpp, the `GET /api/v1/usb-forwarding` capability reply and the rules behind it.
 * @details The MoonlightVibe client parses this body and treats anything outside version 1 as "no host support",
 *          so these tests pin the exact shape. They also pin the decision order and the one rule that matters
 *          most: a port and a token are only ever sent when the client may use the tunnel right now.
 */
#include "../tests_common.h"

#include <src/config.h>
#include <src/nvhttp.h>

#include <cctype>
#include <set>
#include <string>

#include <nlohmann/json.hpp>

namespace {

  using nvhttp::usb_forwarding_inputs;
  using nvhttp::usb_forwarding_state;
  using crypto::PERM;

  const std::string kToken(64, 'a');

  usb_forwarding_inputs ready_inputs() {
    usb_forwarding_inputs inputs;
    inputs.enabled = true;
    inputs.service_running = true;
    inputs.perm = PERM::_default | PERM::usb_forward;
    inputs.require_stream = true;
    inputs.has_active_stream = true;
    return inputs;
  }

  nlohmann::json reply(usb_forwarding_state state, std::uint16_t port = 48100, std::string_view token = {}) {
    return nlohmann::json::parse(nvhttp::usb_forwarding_capability_json(state, port, token.empty() ? std::string_view {kToken} : token));
  }

  void expect_closed_shape(const nlohmann::json &body, bool enabled, const char *reason) {
    ASSERT_TRUE(body.is_object());
    ASSERT_TRUE(body.contains("version"));
    EXPECT_EQ(body["version"], 1);
    ASSERT_TRUE(body["enabled"].is_boolean());
    EXPECT_EQ(body["enabled"].get<bool>(), enabled);
    ASSERT_TRUE(body["available"].is_boolean());
    EXPECT_FALSE(body["available"].get<bool>());
    EXPECT_EQ(body["reason"], reason);
    // The client only reads these when available is true, but a reply that says no must not carry them at all.
    EXPECT_FALSE(body.contains("port"));
    EXPECT_FALSE(body.contains("token"));
  }

  // The permission bits that a client gets without anyone choosing them.
  constexpr PERM kFirstPairedClient = PERM::_all;
  constexpr PERM kLaterPairedClient = PERM::_default;

}  // namespace

// ---- the reply body, state by state ------------------------------------------------------------------------------

TEST(UsbForwardingCapability, ReportsDisabledVersionOne) {
  expect_closed_shape(reply(usb_forwarding_state::disabled), false, "disabled");
}

TEST(UsbForwardingCapability, ReportsUnavailableWhenEnabledButNotUsable) {
  expect_closed_shape(reply(usb_forwarding_state::unavailable), true, "unavailable");
}

TEST(UsbForwardingCapability, ReportsForbiddenForAClientWithoutPermission) {
  expect_closed_shape(reply(usb_forwarding_state::forbidden), true, "forbidden");
}

TEST(UsbForwardingCapability, ReadyCarriesPortAndTokenAndNothingElseUnexpected) {
  const auto body = reply(usb_forwarding_state::ready, 48091);
  EXPECT_EQ(body["version"], 1);
  EXPECT_TRUE(body["enabled"].get<bool>());
  EXPECT_TRUE(body["available"].get<bool>());
  EXPECT_EQ(body["reason"], "ready");
  ASSERT_TRUE(body["port"].is_number_unsigned());
  EXPECT_EQ(body["port"].get<int>(), 48091);
  ASSERT_TRUE(body["token"].is_string());
  EXPECT_EQ(body["token"].get<std::string>(), kToken);
  EXPECT_EQ(body.size(), 6u);
}

TEST(UsbForwardingCapability, EveryStateSpeaksOnlyReasonsTheClientMaps) {
  const std::set<std::string> client_reasons {"disabled", "unavailable", "forbidden", "unauthorized", "busy", "ready"};
  for (const auto state : {usb_forwarding_state::disabled, usb_forwarding_state::unavailable, usb_forwarding_state::forbidden, usb_forwarding_state::ready}) {
    EXPECT_TRUE(client_reasons.contains(reply(state)["reason"].get<std::string>()));
  }
}

TEST(UsbForwardingCapability, OnlyTheReadyStateEverCarriesCredentials) {
  for (const auto state : {usb_forwarding_state::disabled, usb_forwarding_state::unavailable, usb_forwarding_state::forbidden}) {
    const auto body = reply(state, 48091);
    EXPECT_FALSE(body.contains("port"));
    EXPECT_FALSE(body.contains("token"));
    EXPECT_FALSE(body["available"].get<bool>());
    // Even if a caller hands over a perfectly good token, a refusal must not leak it.
    EXPECT_EQ(nvhttp::usb_forwarding_capability_json(state, 48091, kToken).find(kToken), std::string::npos);
  }
}

TEST(UsbForwardingCapability, AReadyStateWithUnusableCredentialsIsDowngradedNotSent) {
  for (const std::string bad_token : {std::string {}, std::string(63, 'a'), std::string(65, 'a'), std::string(64, 'g'), std::string(32, 'a') + " " + std::string(31, 'a')}) {
    SCOPED_TRACE(bad_token);
    const auto body = nlohmann::json::parse(nvhttp::usb_forwarding_capability_json(usb_forwarding_state::ready, 48091, bad_token));
    expect_closed_shape(body, true, "unavailable");
  }
  expect_closed_shape(nlohmann::json::parse(nvhttp::usb_forwarding_capability_json(usb_forwarding_state::ready, 0, kToken)), true, "unavailable");
}

TEST(UsbForwardingCapability, AcceptsUpperAndLowerCaseHexTokens) {
  const std::string mixed = "0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD";
  ASSERT_EQ(mixed.size(), 64u);
  EXPECT_EQ(reply(usb_forwarding_state::ready, 48091, mixed)["reason"], "ready");
}

TEST(UsbForwardingCapability, StaysUnderTheClientsSizeLimit) {
  // The client rejects a body over 4096 bytes.
  for (const auto state : {usb_forwarding_state::disabled, usb_forwarding_state::unavailable, usb_forwarding_state::forbidden, usb_forwarding_state::ready}) {
    EXPECT_LT(nvhttp::usb_forwarding_capability_json(state, 65535, kToken).size(), 4096u);
  }
}

// ---- the decision, branch by branch -----------------------------------------------------------------------------

TEST(UsbForwardingDecision, ReadyWhenEverythingIsInPlace) {
  EXPECT_EQ(nvhttp::usb_forwarding_decide(ready_inputs()), usb_forwarding_state::ready);
}

TEST(UsbForwardingDecision, DisabledWinsOverEverythingElse) {
  auto inputs = ready_inputs();
  inputs.enabled = false;
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::disabled);
  inputs.service_running = false;
  inputs.perm = PERM::_no;
  inputs.has_active_stream = false;
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::disabled);
}

TEST(UsbForwardingDecision, ANotRunningServiceIsUnavailable) {
  auto inputs = ready_inputs();
  inputs.service_running = false;
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::unavailable);
  // Not running is reported before the permission, so a bind failure never reads as "forbidden".
  inputs.perm = PERM::_default;
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::unavailable);
}

TEST(UsbForwardingDecision, AClientWithoutThePermissionIsForbidden) {
  auto inputs = ready_inputs();
  inputs.perm = PERM::_default;
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::forbidden);
  inputs.perm = PERM::_all;  // everything except the opt-in bit
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::forbidden);
  inputs.perm = PERM::_no;
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::forbidden);
}

TEST(UsbForwardingDecision, OtherPermissionBitsDoNotStandInForTheUsbBit) {
  auto inputs = ready_inputs();
  for (const auto bit : {PERM::server_cmd, PERM::file_upload, PERM::file_dwnload, PERM::clipboard_set, PERM::clipboard_read, PERM::launch, PERM::view, PERM::list, PERM::input_kbd}) {
    inputs.perm = bit;
    EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::forbidden) << static_cast<unsigned>(bit);
  }
}

TEST(UsbForwardingDecision, TheUsbBitAloneIsEnough) {
  auto inputs = ready_inputs();
  inputs.perm = PERM::usb_forward;
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::ready);
}

TEST(UsbForwardingDecision, NoStreamIsUnavailableWhenAStreamIsRequired) {
  auto inputs = ready_inputs();
  inputs.has_active_stream = false;
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::unavailable);
}

TEST(UsbForwardingDecision, NoStreamIsFineWhenNotRequired) {
  auto inputs = ready_inputs();
  inputs.require_stream = false;
  inputs.has_active_stream = false;
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::ready);
}

TEST(UsbForwardingDecision, PermissionIsCheckedBeforeTheStream) {
  auto inputs = ready_inputs();
  inputs.perm = PERM::_default;
  inputs.has_active_stream = false;
  EXPECT_EQ(nvhttp::usb_forwarding_decide(inputs), usb_forwarding_state::forbidden);
}

TEST(UsbForwardingDecision, NoPortOrTokenUnlessReady_ExhaustiveOverEveryInput) {
  const PERM perms[] = {PERM::_no, PERM::_default, PERM::_all, PERM::usb_forward, PERM::_default | PERM::usb_forward};
  int ready_count = 0;
  for (const bool enabled : {false, true}) {
    for (const bool running : {false, true}) {
      for (const auto perm : perms) {
        for (const bool require : {false, true}) {
          for (const bool stream : {false, true}) {
            usb_forwarding_inputs inputs;
            inputs.enabled = enabled;
            inputs.service_running = running;
            inputs.perm = perm;
            inputs.require_stream = require;
            inputs.has_active_stream = stream;
            const auto state = nvhttp::usb_forwarding_decide(inputs);
            const auto body = reply(state, 48091);
            const bool should_be_ready = enabled && running && !!(perm & PERM::usb_forward) && (!require || stream);
            EXPECT_EQ(state == usb_forwarding_state::ready, should_be_ready);
            EXPECT_EQ(body.contains("port"), should_be_ready);
            EXPECT_EQ(body.contains("token"), should_be_ready);
            EXPECT_EQ(body["available"].get<bool>(), should_be_ready);
            EXPECT_EQ(body["enabled"].get<bool>(), enabled);
            ready_count += should_be_ready ? 1 : 0;
          }
        }
      }
    }
  }
  EXPECT_GT(ready_count, 0) << "the sweep never reached the ready state, so it proved nothing";
}

TEST(UsbForwardingDecision, TheTunnelAndTheCapabilityReplyAgree) {
  // Same rules, expressed in the tunnel's vocabulary.
  using remote_usb::client_authorization;
  EXPECT_EQ(nvhttp::usb_forwarding_client_authorization(PERM::usb_forward, true, true), client_authorization::allowed);
  EXPECT_EQ(nvhttp::usb_forwarding_client_authorization(PERM::usb_forward, true, false), client_authorization::no_stream);
  EXPECT_EQ(nvhttp::usb_forwarding_client_authorization(PERM::usb_forward, false, false), client_authorization::allowed);
  EXPECT_EQ(nvhttp::usb_forwarding_client_authorization(PERM::_default, true, true), client_authorization::forbidden);
  EXPECT_EQ(nvhttp::usb_forwarding_client_authorization(PERM::_all, false, true), client_authorization::forbidden);
  EXPECT_EQ(nvhttp::usb_forwarding_client_authorization(PERM::_no, false, false), client_authorization::forbidden);
}

// ---- permission defaults -------------------------------------------------------------------------------------------

TEST(UsbForwardingPermission, IsOutsideEveryDefaultAndEveryAllMask) {
  EXPECT_FALSE(!!(PERM::_default & PERM::usb_forward));
  EXPECT_FALSE(!!(PERM::_all & PERM::usb_forward)) << "a client that is first to pair, or that has no stored perm, would get it";
  EXPECT_FALSE(!!(PERM::_all_opeiations & PERM::usb_forward));
  EXPECT_FALSE(!!(PERM::_all_actions & PERM::usb_forward));
  EXPECT_FALSE(!!(PERM::_all_inputs & PERM::usb_forward));
  EXPECT_FALSE(!!(kFirstPairedClient & PERM::usb_forward));
  EXPECT_FALSE(!!(kLaterPairedClient & PERM::usb_forward));
}

TEST(UsbForwardingPermission, IsAKnownBitSoItSurvivesLoadingAndSaving) {
  EXPECT_TRUE(!!(PERM::_storable & PERM::usb_forward));
  EXPECT_TRUE(!!(PERM::_storable & PERM::_all));
  // A single, distinct bit that overlaps no existing permission.
  const auto bit = static_cast<std::uint32_t>(PERM::usb_forward);
  EXPECT_EQ(bit & (bit - 1), 0u);
  EXPECT_EQ(bit & static_cast<std::uint32_t>(PERM::_all), 0u);
}

// ---- the port ----------------------------------------------------------------------------------------------------

TEST(UsbForwardingPort, ZeroMeansTheMainPortPlusSeven) {
  EXPECT_EQ(nvhttp::usb_forwarding_resolve_port(0, 47989), 47996);
  EXPECT_EQ(nvhttp::usb_forwarding_resolve_port(0, 48100), 48107);
}

TEST(UsbForwardingPort, ASevenOffsetThatLeavesTheValidRangeIsRefused) {
  EXPECT_FALSE(nvhttp::usb_forwarding_resolve_port(0, 65530).has_value());
  EXPECT_FALSE(nvhttp::usb_forwarding_resolve_port(0, 1000).has_value());
}

TEST(UsbForwardingPort, ExplicitPortsMustBeInRange) {
  EXPECT_EQ(nvhttp::usb_forwarding_resolve_port(1024, 47989), 1024);
  EXPECT_EQ(nvhttp::usb_forwarding_resolve_port(65535, 47989), 65535);
  EXPECT_FALSE(nvhttp::usb_forwarding_resolve_port(1023, 47989).has_value());
  EXPECT_FALSE(nvhttp::usb_forwarding_resolve_port(-1, 47989).has_value());
  EXPECT_FALSE(nvhttp::usb_forwarding_resolve_port(65536, 47989).has_value());
  EXPECT_FALSE(nvhttp::usb_forwarding_resolve_port(100000, 47989).has_value());
}

TEST(UsbForwardingPort, NeverCollidesWithAPortTheHostUsesItself) {
  constexpr int main_port = 47989;
  // -5 (HTTPS), 0 (HTTP), +1 (web UI), +9..+12 (video, control, audio, mic) and +26 (RTSP).
  for (const int offset : {-5, 0, 1, 9, 10, 11, 12, 26}) {
    SCOPED_TRACE(offset);
    EXPECT_FALSE(nvhttp::usb_forwarding_resolve_port(main_port + offset, main_port).has_value());
  }
  // The neighbours that are free are fine.
  for (const int offset : {-4, 2, 7, 8, 13, 25, 27}) {
    SCOPED_TRACE(offset);
    EXPECT_EQ(nvhttp::usb_forwarding_resolve_port(main_port + offset, main_port), main_port + offset);
  }
}

TEST(UsbForwardingPort, TheDefaultIsNeverOneOfTheReservedOffsets) {
  for (int main_port = 1100; main_port < 65500; main_port += 97) {
    const auto port = nvhttp::usb_forwarding_resolve_port(0, static_cast<std::uint16_t>(main_port));
    ASSERT_TRUE(port.has_value());
    EXPECT_EQ(*port, main_port + 7);
  }
}

// ---- the token ---------------------------------------------------------------------------------------------------

TEST(UsbForwardingToken, IsSixtyFourHexDigitsAndStableForTheProcess) {
  const auto &token = nvhttp::usb_forwarding_token();
  ASSERT_EQ(token.size(), 64u);
  for (const unsigned char c : token) {
    EXPECT_TRUE(std::isxdigit(c) && !std::isupper(c)) << c;
  }
  EXPECT_EQ(&token, &nvhttp::usb_forwarding_token());
  EXPECT_NE(token, std::string(64, '0'));
  // What the client would accept.
  EXPECT_EQ(reply(usb_forwarding_state::ready, 48091, token)["reason"], "ready");
}

// ---- configuration -----------------------------------------------------------------------------------------------

TEST(UsbForwardingConfig, DefaultsAreOffAutomaticPortAndStreamRequired) {
  const config::nvhttp_t defaults;
  EXPECT_FALSE(defaults.usb_forwarding_enabled);
  EXPECT_EQ(defaults.usb_forwarding_port, 0);
  EXPECT_TRUE(defaults.usb_forwarding_require_stream);
}

TEST(UsbForwardingConfig, TheRunningConfigStartsOff) {
  // Nothing in the test environment turns it on, so a default host starts no listener.
  EXPECT_FALSE(config::nvhttp.usb_forwarding_enabled);
  EXPECT_EQ(config::nvhttp.usb_forwarding_port, 0);
  EXPECT_TRUE(config::nvhttp.usb_forwarding_require_stream);
}

TEST(UsbForwardingConfig, ThePortOptionAcceptsZeroAndTheUnprivilegedRange) {
  EXPECT_EQ(config::parse_usb_forwarding_port("0"), 0);
  EXPECT_EQ(config::parse_usb_forwarding_port("1024"), 1024);
  EXPECT_EQ(config::parse_usb_forwarding_port("47996"), 47996);
  EXPECT_EQ(config::parse_usb_forwarding_port("65535"), 65535);
  EXPECT_EQ(config::parse_usb_forwarding_port("\"48100\""), 48100);
}

TEST(UsbForwardingConfig, AnInvalidPortFallsBackToAutomatic) {
  for (const char *bad : {"1", "80", "1023", "65536", "99999999999", "-5", "abc", "12ab", "", " 4000", "4000 ", "0x4000", "40.5", "+4000"}) {
    SCOPED_TRACE(bad);
    EXPECT_EQ(config::parse_usb_forwarding_port(bad), 0);
  }
}

TEST(UsbForwardingConfig, ParsesFromAConfigFile) {
  auto vars = config::parse_config("usb_forwarding_enabled = enabled\nusb_forwarding_port = 48100\nusb_forwarding_require_stream = disabled\n");
  EXPECT_EQ(vars.at("usb_forwarding_enabled"), "enabled");
  EXPECT_EQ(vars.at("usb_forwarding_port"), "48100");
  EXPECT_EQ(vars.at("usb_forwarding_require_stream"), "disabled");
}
