/**
 * @file tests/unit/test_usbip_executable.cpp
 * @brief Tests for the usbip.exe trust check (src/remote_usb/usbip_executable.cpp).
 * @details The checks run against real files and real ACLs created under the temp directory. The positive case
 *          uses a stock system file, whose location only administrators can change.
 */
#ifdef _WIN32

  #include <src/remote_usb/usbip_executable.h>

  #include <cstdlib>
  #include <filesystem>
  #include <fstream>
  #include <string>

  // clang-format off
  #include <windows.h>
  #include <aclapi.h>
  #include <sddl.h>
  // clang-format on

  #include <gtest/gtest.h>

namespace {

  namespace fs = std::filesystem;

  std::string system_file(const char *relative) {
    const char *root = std::getenv("SystemRoot");
    return std::string(root ? root : "C:\\Windows") + "\\" + relative;
  }

  struct temp_dir {
    fs::path path;

    explicit temp_dir(const char *name) {
      path = fs::temp_directory_path() / (std::string("apollovibe_usbip_exe_") + name);
      std::error_code ignored;
      fs::remove_all(path, ignored);
      fs::create_directories(path);
    }

    ~temp_dir() {
      // A test may have replaced the ACL; take it back before deleting.
      reset_acl(path.wstring());
      std::error_code ignored;
      fs::remove_all(path, ignored);
    }

    static void reset_acl(const std::wstring &object) {
      PSECURITY_DESCRIPTOR descriptor = nullptr;
      if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;FA;;;WD)", SDDL_REVISION_1, &descriptor, nullptr)) {
        BOOL present = FALSE, defaulted = FALSE;
        PACL dacl = nullptr;
        GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted);
        SetNamedSecurityInfoW(const_cast<wchar_t *>(object.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
        LocalFree(descriptor);
      }
    }
  };

  /**
   * Replace the owner and the DACL of a file or directory. SDDL describes both, for example
   * "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)". Returns false when this process may not do that.
   */
  bool stage_security(const fs::path &object, const wchar_t *sddl, bool set_owner = true) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, nullptr)) {
      return false;
    }
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    PSID owner = nullptr;
    GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted);
    GetSecurityDescriptorOwner(descriptor, &owner, &defaulted);
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if (set_owner) {
      information |= OWNER_SECURITY_INFORMATION;
    }
    const std::wstring wide = object.wstring();
    const DWORD status = SetNamedSecurityInfoW(const_cast<wchar_t *>(wide.c_str()), SE_FILE_OBJECT, information, set_owner ? owner : nullptr, nullptr, present ? dacl : nullptr, nullptr);
    LocalFree(descriptor);
    return status == ERROR_SUCCESS;
  }

  // Owner Administrators, full control for SYSTEM and Administrators only.
  constexpr const wchar_t *kLockedDown = L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

}  // namespace

TEST(UsbipExecutable, AcceptsAStockSystemFile) {
  const auto cmd = system_file("System32\\cmd.exe");
  const auto check = remote_usb::check_trusted_executable(cmd, "cmd.exe");
  EXPECT_TRUE(check.ok) << check.detail;
}

TEST(UsbipExecutable, TheFileNameMustMatchExactly) {
  const auto cmd = system_file("System32\\cmd.exe");
  EXPECT_FALSE(remote_usb::check_trusted_executable(cmd, "usbip.exe").ok);
  EXPECT_TRUE(remote_usb::check_trusted_executable(cmd, "CMD.EXE").ok) << "the comparison ignores case, like the file system";
}

TEST(UsbipExecutable, RefusesPathsThatAreNotPlainAbsoluteDriveLetterPaths) {
  const auto cmd = system_file("System32\\cmd.exe");
  const std::string bad_paths[] = {
    "",
    "cmd.exe",
    "System32\\cmd.exe",
    "\\Windows\\System32\\cmd.exe",
    "C:cmd.exe",
    "\\\\localhost\\C$\\Windows\\System32\\cmd.exe",
    "\\\\?\\" + cmd,
    "\\\\.\\C:\\Windows\\System32\\cmd.exe",
    system_file("System32\\..\\System32\\cmd.exe"),
    system_file("System32\\.\\cmd.exe"),
    "%SystemRoot%\\System32\\cmd.exe",
    "\"" + cmd + "\"",
    cmd + ":evil",
    cmd + "\n",
    std::string("C:/Windows/System32/cmd.exe"),
    system_file("System32\\") + "cmd.exe\\",
  };
  for (const auto &path : bad_paths) {
    SCOPED_TRACE(path);
    const auto check = remote_usb::check_trusted_executable(path, "cmd.exe");
    EXPECT_FALSE(check.ok);
    EXPECT_FALSE(check.detail.empty());
  }
}

TEST(UsbipExecutable, RefusesAFileThatDoesNotExistAndADirectory) {
  EXPECT_FALSE(remote_usb::check_trusted_executable(system_file("System32\\no_such_file_apollovibe\\cmd.exe"), "cmd.exe").ok);
  EXPECT_FALSE(remote_usb::check_trusted_executable(system_file("System32\\no_such_cmd_apollovibe.exe"), "no_such_cmd_apollovibe.exe").ok);
  // A directory with the right name.
  temp_dir dir("dirname");
  fs::create_directories(dir.path / "usbip.exe");
  const auto check = remote_usb::check_trusted_executable((dir.path / "usbip.exe").string(), "usbip.exe");
  EXPECT_FALSE(check.ok);
}

TEST(UsbipExecutable, RefusesAFileInAUserWritableDirectory) {
  temp_dir dir("userwritable");
  { std::ofstream(dir.path / "usbip.exe") << "x"; }
  const auto check = remote_usb::check_trusted_executable((dir.path / "usbip.exe").string(), "usbip.exe");
  ASSERT_FALSE(check.ok);
  EXPECT_NE(check.detail.find("changed by users"), std::string::npos) << check.detail;
}

TEST(UsbipExecutable, RefusesAPathThroughAJunction) {
  temp_dir dir("junction");
  const auto link = dir.path / "linked";
  const auto command = "mklink /J \"" + link.string() + "\" \"" + system_file("System32") + "\" > nul 2>&1";
  if (std::system(("cmd /c " + command).c_str()) != 0 || !fs::exists(link)) {
    GTEST_SKIP() << "could not create a junction";
  }
  const auto check = remote_usb::check_trusted_executable((link / "cmd.exe").string(), "cmd.exe");
  ASSERT_FALSE(check.ok);
  EXPECT_NE(check.detail.find("link"), std::string::npos) << check.detail;
  // Remove the junction itself, not its target.
  RemoveDirectoryW(link.wstring().c_str());
}

TEST(UsbipExecutable, RefusesAPathThroughASubstDrive) {
  char letter = 0;
  for (char candidate = 'Y'; candidate >= 'P'; --candidate) {
    const std::string root = std::string(1, candidate) + ":\\";
    if (GetDriveTypeA(root.c_str()) == DRIVE_NO_ROOT_DIR) {
      letter = candidate;
      break;
    }
  }
  if (letter == 0) {
    GTEST_SKIP() << "no free drive letter";
  }
  const std::string device = std::string(1, letter) + ":";
  const auto target = system_file("System32");
  if (!DefineDosDeviceA(0, device.c_str(), target.c_str())) {
    GTEST_SKIP() << "could not define a DOS device";
  }
  const auto check = remote_usb::check_trusted_executable(device + "\\cmd.exe", "cmd.exe");
  DefineDosDeviceA(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, device.c_str(), target.c_str());
  ASSERT_FALSE(check.ok);
  EXPECT_NE(check.detail.find("link"), std::string::npos) << check.detail;
}

TEST(UsbipExecutable, RefusesAShortNameAlias) {
  temp_dir dir("a long directory name for the alias");
  { std::ofstream(dir.path / "usbip.exe") << "x"; }
  wchar_t buffer[MAX_PATH * 2] = {};
  const auto length = GetShortPathNameW((dir.path / "usbip.exe").wstring().c_str(), buffer, MAX_PATH * 2);
  if (length == 0 || length >= MAX_PATH * 2) {
    GTEST_SKIP() << "no short names on this volume";
  }
  std::string alias;
  for (const wchar_t *c = buffer; *c; ++c) {
    alias.push_back(static_cast<char>(*c));
  }
  if (alias.find('~') == std::string::npos) {
    GTEST_SKIP() << "8.3 names are disabled on this volume";
  }
  const auto check = remote_usb::check_trusted_executable(alias, "usbip.exe");
  ASSERT_FALSE(check.ok);
  EXPECT_NE(check.detail.find("alias"), std::string::npos) << check.detail;
}

TEST(UsbipExecutable, ADirectoryOnlyAdministratorsCanChangeIsNotWritable) {
  temp_dir dir("lockeddown");
  if (!stage_security(dir.path, kLockedDown)) {
    GTEST_SKIP() << "this process may not set the owner and ACL (needs an elevated administrator)";
  }
  EXPECT_FALSE(remote_usb::object_writable_by_untrusted(dir.path.wstring(), true, false));
}

TEST(UsbipExecutable, AnAllowEntryForUsersOrEveryoneMakesItWritable) {
  const wchar_t *sddls[] = {
    L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)",  // Users: modify
    L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)",        // Everyone: full control
    L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GW;;;AU)",        // Authenticated Users: generic write
    L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;IU)",        // Interactive: full control
    L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;WD;;;BU)",            // Users: DELETE-class right via WRITE_DAC? (WD = WRITE_DAC)
    L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;DC;;;BU)",            // Users: delete child
  };
  for (const auto *sddl : sddls) {
    SCOPED_TRACE(::testing::PrintToString(std::wstring(sddl).size()));
    temp_dir dir("allowentry");
    if (!stage_security(dir.path, sddl)) {
      GTEST_SKIP() << "this process may not set the owner and ACL (needs an elevated administrator)";
    }
    EXPECT_TRUE(remote_usb::object_writable_by_untrusted(dir.path.wstring(), true, false));
  }
}

TEST(UsbipExecutable, ReadAndExecuteForUsersIsStillTrusted) {
  temp_dir dir("readonly");
  if (!stage_security(dir.path, L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;GR;;;WD)")) {
    GTEST_SKIP() << "this process may not set the owner and ACL (needs an elevated administrator)";
  }
  EXPECT_FALSE(remote_usb::object_writable_by_untrusted(dir.path.wstring(), true, false));
}

TEST(UsbipExecutable, AnInheritOnlyEntryDoesNotApplyToTheObjectItself) {
  temp_dir dir("inheritonly");
  // Users get full control on children only (the shape Program Files uses for CREATOR OWNER).
  if (!stage_security(dir.path, L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;BU)")) {
    GTEST_SKIP() << "this process may not set the owner and ACL (needs an elevated administrator)";
  }
  EXPECT_FALSE(remote_usb::object_writable_by_untrusted(dir.path.wstring(), true, false));
}

TEST(UsbipExecutable, AnOwnerThatIsNotAdministratorsMakesItWritable) {
  temp_dir dir("owner");
  // The owner is this process's own user: it can rewrite the ACL no matter what the entries say.
  HANDLE token = nullptr;
  ASSERT_TRUE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::string buffer(size, '\0');
  ASSERT_TRUE(GetTokenInformation(token, TokenUser, buffer.data(), size, &size));
  CloseHandle(token);
  LPWSTR user_sid_text = nullptr;
  ASSERT_TRUE(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &user_sid_text));
  const std::wstring sddl = std::wstring(L"O:") + user_sid_text + L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
  LocalFree(user_sid_text);
  if (!stage_security(dir.path, sddl.c_str())) {
    GTEST_SKIP() << "could not set the owner";
  }
  EXPECT_TRUE(remote_usb::object_writable_by_untrusted(dir.path.wstring(), true, false));
}

TEST(UsbipExecutable, ANullDaclAndAMissingObjectCountAsWritable) {
  temp_dir dir("nulldacl");
  const std::wstring wide = dir.path.wstring();
  // A NULL DACL (as opposed to an empty one) grants everyone full access.
  ASSERT_EQ(SetNamedSecurityInfoW(const_cast<wchar_t *>(wide.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr), ERROR_SUCCESS);
  EXPECT_TRUE(remote_usb::object_writable_by_untrusted(wide, true, false));
  EXPECT_TRUE(remote_usb::object_writable_by_untrusted((dir.path / "missing").wstring(), true, false));
}

TEST(UsbipExecutable, AFileIsJudgedByFileRightsAndTheDriveRootByItsOwnNarrowerRule) {
  // C:\ lets Authenticated Users create folders, which cannot replace an existing child.
  EXPECT_FALSE(remote_usb::object_writable_by_untrusted(L"C:\\", true, true));
  const auto cmd = system_file("System32\\cmd.exe");
  EXPECT_FALSE(remote_usb::object_writable_by_untrusted(std::wstring(cmd.begin(), cmd.end()), false, false));
  // The same root judged as an ordinary directory would be writable by Authenticated Users on a default install,
  // which is why the narrower mask exists. Only assert the direction that matters: the root rule is not looser.
  temp_dir dir("rootrule");
  EXPECT_TRUE(remote_usb::object_writable_by_untrusted(dir.path.wstring(), true, true)) << "a user-owned temp directory is writable under the root rule too";
}

TEST(UsbipExecutable, TheKnownPathLivesUnderProgramFilesAndNamesUsbipExe) {
  const auto path = remote_usb::known_usbip_executable_path();
  ASSERT_FALSE(path.empty());
  EXPECT_EQ(path.substr(1, 2), ":\\");
  EXPECT_NE(path.find("\\USBip\\usbip.exe"), std::string::npos);
  // It is not required to exist here (the driver is not installed on a build machine), but if it does
  // the check must not crash and must give a reason when it refuses.
  const auto check = remote_usb::check_trusted_executable(path, "usbip.exe");
  if (!check.ok) {
    EXPECT_FALSE(check.detail.empty());
  }
}

#endif  // _WIN32
