/**
 * @file tests/integration/test_pin_permissions.cpp
 * @brief The device-management page must mirror the C++ permission bits, or saving a client would change them.
 */
#include "../tests_common.h"

#include <src/crypto.h>
#include <src/file_handler.h>

#include <cstdint>
#include <regex>
#include <string>

namespace {

  std::uint32_t mapping_value(const std::string &page, const std::string &name) {
    const std::regex pattern("\\b" + name + R"X(:\s*0x([0-9A-Fa-f]+))X");
    std::smatch match;
    if (!std::regex_search(page, match, pattern)) {
      ADD_FAILURE() << "pin.html has no permissionMapping entry named " << name;
      return 0;
    }
    return static_cast<std::uint32_t>(std::stoul(match[1].str(), nullptr, 16));
  }

}  // namespace

TEST(PinPermissions, TheMappingMatchesTheCppBits) {
  const auto page = file_handler::read_file("src_assets/common/assets/web/pin.html");
  ASSERT_FALSE(page.empty());
  EXPECT_EQ(mapping_value(page, "usb_forward"), static_cast<std::uint32_t>(crypto::PERM::usb_forward));
  EXPECT_EQ(mapping_value(page, "_all"), static_cast<std::uint32_t>(crypto::PERM::_all));
  EXPECT_EQ(mapping_value(page, "_default"), static_cast<std::uint32_t>(crypto::PERM::_default));
  EXPECT_EQ(mapping_value(page, "_storable"), static_cast<std::uint32_t>(crypto::PERM::_storable));
}

TEST(PinPermissions, TheOptInBitIsOutsideAllAndDefaultOnThePageToo) {
  const auto page = file_handler::read_file("src_assets/common/assets/web/pin.html");
  const auto usb = mapping_value(page, "usb_forward");
  EXPECT_EQ(usb & mapping_value(page, "_all"), 0u);
  EXPECT_EQ(usb & mapping_value(page, "_default"), 0u);
  EXPECT_EQ(usb & mapping_value(page, "_all_operations"), 0u);
}

TEST(PinPermissions, SavingAClientKeepsTheOptInBit) {
  const auto page = file_handler::read_file("src_assets/common/assets/web/pin.html");
  // The mask applied to the value sent to the server must be the one that includes the opt-in bit.
  EXPECT_NE(page.find("client.editPerm & permissionMapping._storable"), std::string::npos);
  EXPECT_EQ(page.find("client.editPerm & permissionMapping._all,"), std::string::npos);
}

TEST(PinPermissions, TheTogglesAreShownWithAWarning) {
  const auto page = file_handler::read_file("src_assets/common/assets/web/pin.html");
  EXPECT_NE(page.find("name: 'usb_forward'"), std::string::npos);
  EXPECT_NE(page.find("permissions.usb_forward_warning"), std::string::npos);
  const auto locale = file_handler::read_file("src_assets/common/assets/web/public/assets/locale/en.json");
  EXPECT_NE(locale.find("\"usb_forward\":"), std::string::npos);
  const auto warning = locale.find("\"usb_forward_warning\":");
  ASSERT_NE(warning, std::string::npos);
  EXPECT_NE(locale.find("Equivalent to plugging a USB device into this host", warning), std::string::npos);
}
