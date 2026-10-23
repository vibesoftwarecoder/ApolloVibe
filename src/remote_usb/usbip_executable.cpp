/**
 * @file src/remote_usb/usbip_executable.cpp
 * @brief Trust check for the usbip.exe path (Windows only).
 *
 * The directory-walk idea follows the MoonlightVibe client's usbipd check.
 * The difference is the identity it judges by: Apollo runs as SYSTEM, whose own
 * token can write almost everywhere, so access is not evaluated with the
 * process token.  Instead the DACL is read directly and any allow entry for a
 * principal outside {SYSTEM, Administrators, TrustedInstaller} that grants a
 * write-class right makes the location untrusted.  Deny entries are ignored on
 * purpose: that can only make the check stricter.
 */
#ifdef _WIN32

  #include "usbip_executable.h"

  #include <memory>
  #include <vector>

  // clang-format off
  #include <windows.h>
  #include <accctrl.h>
  #include <aclapi.h>
  #include <sddl.h>
  #include <shlobj.h>
  // clang-format on

namespace remote_usb {
  namespace {

    // Rights that change an object, or what a directory contains. The directory-only bits
    // share values with the file ones (FILE_ADD_FILE is FILE_WRITE_DATA, FILE_ADD_SUBDIRECTORY
    // is FILE_APPEND_DATA), so one mask covers both.
    constexpr DWORD kFileModifyMask = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
    constexpr DWORD kDirectoryModifyMask = kFileModifyMask | FILE_DELETE_CHILD;
    // On a drive root every user may add folders by default; that cannot replace an existing
    // child. Only rights that can remove or re-permission existing children matter.
    constexpr DWORD kRootModifyMask = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;

    struct local_free_deleter {
      void operator()(void *pointer) const {
        if (pointer) {
          LocalFree(pointer);
        }
      }
    };
    using local_memory = std::unique_ptr<void, local_free_deleter>;

    struct handle_deleter {
      void operator()(HANDLE handle) const {
        if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
          CloseHandle(handle);
        }
      }
    };
    using unique_handle = std::unique_ptr<void, handle_deleter>;

    // The principals allowed to own or change the location.
    class trusted_sids {
    public:
      trusted_sids() {
        add_well_known(WinLocalSystemSid);
        add_well_known(WinBuiltinAdministratorsSid);
        PSID installer = nullptr;
        if (ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &installer)) {
          owned_.emplace_back(installer);
        }
        ok_ = owned_.size() == 3;
      }

      // False when the list could not be built; callers must then refuse.
      bool ok() const {
        return ok_;
      }

      bool contains(PSID sid) const {
        for (const auto &trusted : owned_) {
          if (EqualSid(trusted.get(), sid)) {
            return true;
          }
        }
        return false;
      }

    private:
      void add_well_known(WELL_KNOWN_SID_TYPE type) {
        DWORD size = SECURITY_MAX_SID_SIZE;
        auto *sid = static_cast<PSID>(LocalAlloc(LPTR, size));
        if (sid && CreateWellKnownSid(type, nullptr, sid, &size)) {
          owned_.emplace_back(sid);
        } else if (sid) {
          LocalFree(sid);
        }
      }

      std::vector<local_memory> owned_;
      bool ok_ {false};
    };

    std::wstring widen(std::string_view text) {
      if (text.empty()) {
        return {};
      }
      const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
      if (length <= 0) {
        return {};
      }
      std::wstring result(static_cast<std::size_t>(length), L'\0');
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), length);
      return result;
    }

    std::string narrow(const std::wstring &text) {
      if (text.empty()) {
        return {};
      }
      const int length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
      if (length <= 0) {
        return {};
      }
      std::string result(static_cast<std::size_t>(length), '\0');
      WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), length, nullptr, nullptr);
      return result;
    }

    bool equal_ignoring_case(const std::wstring &left, const std::wstring &right) {
      return CompareStringOrdinal(left.data(), static_cast<int>(left.size()), right.data(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
    }

    // "C:\..." only. Rejects relative, drive-relative, UNC, \\?\ and \\.\ forms.
    bool is_drive_letter_absolute(const std::wstring &path) {
      return path.size() >= 3 && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) && path[1] == L':' && path[2] == L'\\';
    }

    bool has_unsafe_characters(const std::wstring &path) {
      for (std::size_t i = 0; i < path.size(); ++i) {
        const wchar_t c = path[i];
        if (c < 0x20 || c == L'%' || c == L'"' || c == L'<' || c == L'>' || c == L'|' || c == L'*' || c == L'?' || c == L'/') {
          return true;
        }
        if (c == L':' && i != 1) {
          return true;  // alternate data stream or device syntax
        }
      }
      return false;
    }

    // Splits on backslashes. Empty, "." and ".." components are all refused by the caller.
    std::vector<std::wstring> components_of(const std::wstring &path) {
      std::vector<std::wstring> parts;
      std::wstring current;
      for (std::size_t i = 3; i < path.size(); ++i) {
        if (path[i] == L'\\') {
          parts.push_back(current);
          current.clear();
        } else {
          current.push_back(path[i]);
        }
      }
      parts.push_back(current);
      return parts;
    }

    // The path the file system really resolves to, with every junction, symbolic link, subst
    // drive and 8.3 alias followed. Empty on failure or for a network path.
    std::wstring final_path_of(const std::wstring &path) {
      unique_handle handle(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
      if (handle.get() == INVALID_HANDLE_VALUE) {
        return {};
      }
      std::wstring buffer(1024, L'\0');
      DWORD length = GetFinalPathNameByHandleW(handle.get(), buffer.data(), static_cast<DWORD>(buffer.size()), VOLUME_NAME_DOS);
      if (length >= buffer.size()) {
        buffer.assign(static_cast<std::size_t>(length) + 1, L'\0');
        length = GetFinalPathNameByHandleW(handle.get(), buffer.data(), static_cast<DWORD>(buffer.size()), VOLUME_NAME_DOS);
      }
      if (length == 0 || length >= buffer.size()) {
        return {};
      }
      std::wstring result(buffer.c_str(), length);
      if (result.rfind(L"\\\\?\\UNC\\", 0) == 0) {
        return {};
      }
      if (result.rfind(L"\\\\?\\", 0) == 0) {
        result.erase(0, 4);
      }
      return result;
    }

    bool is_directory_path(const std::wstring &path, bool &exists) {
      const DWORD attributes = GetFileAttributesW(path.c_str());
      exists = attributes != INVALID_FILE_ATTRIBUTES;
      return exists && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

  }  // namespace

  std::string known_usbip_executable_path() {
    // FOLDERID_ProgramFilesX64. Declared here so the build does not depend on libuuid.
    static const GUID program_files_x64 = {0x6D809377, 0x6AF0, 0x444B, {0x89, 0x57, 0xA3, 0x77, 0x3F, 0x02, 0x20, 0x0E}};
    PWSTR folder = nullptr;
    if (FAILED(SHGetKnownFolderPath(program_files_x64, KF_FLAG_DEFAULT, nullptr, &folder)) || !folder) {
      if (folder) {
        CoTaskMemFree(folder);
      }
      return {};
    }
    std::wstring path(folder);
    CoTaskMemFree(folder);
    if (!is_drive_letter_absolute(path + L"\\")) {
      return {};
    }
    while (!path.empty() && path.back() == L'\\') {
      path.pop_back();
    }
    return narrow(path + L"\\USBip\\usbip.exe");
  }

  bool object_writable_by_untrusted(const std::wstring &path, bool is_directory, bool is_drive_root) {
    const trusted_sids trusted;
    if (!trusted.ok()) {
      return true;
    }

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    const DWORD status = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
    local_memory descriptor_guard(descriptor);
    if (status != ERROR_SUCCESS || descriptor == nullptr || owner == nullptr) {
      return true;
    }
    // The owner can always rewrite the DACL.
    if (!trusted.contains(owner)) {
      return true;
    }
    // A null DACL grants everyone full access.
    if (dacl == nullptr) {
      return true;
    }

    const DWORD modify_mask = is_drive_root ? kRootModifyMask : (is_directory ? kDirectoryModifyMask : kFileModifyMask);
    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};

    for (DWORD index = 0; index < dacl->AceCount; ++index) {
      void *entry = nullptr;
      if (!GetAce(dacl, index, &entry) || entry == nullptr) {
        return true;
      }
      const auto *header = static_cast<const ACE_HEADER *>(entry);
      const bool allow = header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_ALLOWED_COMPOUND_ACE_TYPE || header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE || header->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE || header->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE;
      if (!allow) {
        continue;
      }
      // An inherit-only entry applies to children, not to this object.
      if ((header->AceFlags & INHERIT_ONLY_ACE) != 0) {
        continue;
      }
      if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_ALLOWED_CALLBACK_ACE_TYPE) {
        return true;  // layouts not parsed here; refuse
      }
      const auto *ace = static_cast<const ACCESS_ALLOWED_ACE *>(entry);
      PSID sid = const_cast<DWORD *>(&ace->SidStart);
      if (!IsValidSid(sid)) {
        return true;
      }
      DWORD mask = ace->Mask;
      MapGenericMask(&mask, &mapping);
      if ((mask & modify_mask) != 0 && !trusted.contains(sid)) {
        return true;
      }
    }
    return false;
  }

  executable_check check_trusted_executable(const std::string &path, std::string_view expected_file_name) {
    const auto refuse = [](const char *why) {
      return executable_check {false, why};
    };

    if (path.empty()) {
      return refuse("no path");
    }
    const std::wstring wide = widen(path);
    if (wide.empty()) {
      return refuse("path is not valid UTF-8");
    }
    if (!is_drive_letter_absolute(wide)) {
      return refuse("not an absolute drive-letter path");
    }
    if (has_unsafe_characters(wide)) {
      return refuse("path contains unsafe characters");
    }
    const auto parts = components_of(wide);
    for (const auto &part : parts) {
      if (part.empty() || part == L"." || part == L"..") {
        return refuse("path has an empty or relative component");
      }
    }
    if (!equal_ignoring_case(parts.back(), widen(expected_file_name))) {
      return refuse("file name is not the expected one");
    }

    bool exists = false;
    if (is_directory_path(wide, exists) || !exists) {
      return refuse("file does not exist");
    }
    const std::wstring resolved = final_path_of(wide);
    if (resolved.empty()) {
      return refuse("file cannot be opened");
    }
    if (!equal_ignoring_case(resolved, wide)) {
      return refuse("path goes through a link, junction, subst drive or alias");
    }

    // The file, then every directory above it up to and including the drive root.
    std::wstring current = wide;
    bool first = true;
    for (;;) {
      const bool root = current.size() == 3;  // "C:\"
      if (object_writable_by_untrusted(current, !first, root)) {
        return refuse(first ? "file can be changed by users other than administrators" : "a directory above the file can be changed by users other than administrators");
      }
      if (root) {
        return executable_check {true, {}};
      }
      const auto slash = current.find_last_of(L'\\');
      if (slash == std::wstring::npos) {
        return refuse("path has no drive root");
      }
      current.erase(slash);
      if (current.size() == 2) {
        current.push_back(L'\\');
      }
      first = false;
    }
  }

}  // namespace remote_usb

#endif  // _WIN32
