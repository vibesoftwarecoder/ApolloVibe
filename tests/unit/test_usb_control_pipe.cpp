/**
 * @file tests/unit/test_usb_control_pipe.cpp
 * @brief Behaviour tests for the USB control pipe (src/remote_usb/usb_control_pipe.cpp).
 * @details Real named pipes, real security descriptors, real clients. Most tests grant the current user an
 *          extra entry through the test-only `test_extra_allowed_sid`, so they run with or without elevation.
 *          The tests about WHO may connect use the production access list (SYSTEM and Administrators only)
 *          and a restricted token, and work in both cases too.
 */
#include "../tests_common.h"

#include <src/config.h>

#ifdef _WIN32

  #include <src/logging.h>
  #include <src/network.h>
  #include <src/nvhttp.h>
  #include <src/remote_usb/usb_control_pipe.h>
  #include <src/remote_usb/usb_tunnel_manager.h>

  #include <atomic>
  #include <chrono>
  #include <fstream>
  #include <iterator>
  #include <algorithm>
  #include <functional>
  #include <memory>
  #include <mutex>
  #include <optional>
  #include <set>
  #include <string>
  #include <thread>
  #include <vector>

  #include <nlohmann/json.hpp>
  #include <openssl/bio.h>
  #include <openssl/evp.h>
  #include <openssl/pem.h>
  #include <openssl/x509.h>

  // clang-format off
  #include <windows.h>
  #include <aclapi.h>
  #include <sddl.h>
  // clang-format on

namespace {

  using namespace std::chrono_literals;
  using remote_usb::control_status;
  using remote_usb::usb_control_backend;
  using remote_usb::usb_control_pipe;
  using remote_usb::usb_control_pipe_config;

  // ---- helpers ----------------------------------------------------------------------------------------------

  std::wstring
  unique_pipe_name() {
    static std::atomic<int> counter {0};
    return L"\\\\.\\pipe\\ApolloVibe-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++counter);
  }

  std::wstring
  current_user_sid_text() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
      return {};
    }
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<char> buffer(size);
    std::wstring text;
    if (GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
      LPWSTR raw = nullptr;
      if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &raw)) {
        text = raw;
        LocalFree(raw);
      }
    }
    CloseHandle(token);
    return text;
  }

  bool
  process_is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
      return false;
    }
    TOKEN_ELEVATION elevation {};
    DWORD size = 0;
    const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) && elevation.TokenIsElevated;
    CloseHandle(token);
    return ok;
  }

  /** A backend that records what it was asked and answers from canned data. */
  class fake_backend: public usb_control_backend {
  public:
    control_status
    status() override {
      ++status_calls;
      if (on_status) {
        on_status();
      }
      const std::lock_guard lock {mutex};
      return canned;
    }
    remote_usb::set_enabled_outcome
    set_enabled(bool enabled) override {
      const std::lock_guard lock {mutex};
      set_calls.push_back(enabled);
      if (set_error == remote_usb::control_error::none) {
        canned.enabled = enabled;
      }
      return {set_error, false};
    }
    remote_usb::revoke_outcome
    revoke_client(const std::string &uuid) override {
      const std::lock_guard lock {mutex};
      revoked.push_back(uuid);
      return {revoke_error, revoke_result, revoke_known};
    }
    remote_usb::clear_outcome
    clear_revoke(const std::string &uuid) override {
      const std::lock_guard lock {mutex};
      cleared.push_back(uuid);
      return {clear_error, revoke_known};
    }

    std::atomic<int> status_calls {0};
    std::function<void()> on_status;
    std::mutex mutex;
    control_status canned;
    remote_usb::control_error set_error {remote_usb::control_error::none};
    std::vector<bool> set_calls;
    std::vector<std::string> revoked;
    std::size_t revoke_result {2};
    bool revoke_known {true};
    remote_usb::control_error revoke_error {remote_usb::control_error::none};
    remote_usb::control_error clear_error {remote_usb::control_error::none};
    std::vector<std::string> cleared;

    std::size_t
    calls() {
      const std::lock_guard lock {mutex};
      return status_calls.load() + set_calls.size() + revoked.size();
    }
  };

  /** A client end of the pipe with overlapped I/O, so a test can never hang on a silent server. */
  class client {
  public:
    explicit client(const std::wstring &name, DWORD access = GENERIC_READ | GENERIC_WRITE) {
      for (int attempt = 0; attempt < 5; ++attempt) {
        handle_ = CreateFileW(name.c_str(), access, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        if (handle_ != INVALID_HANDLE_VALUE) {
          error_ = ERROR_SUCCESS;
          return;
        }
        error_ = GetLastError();
        if (error_ != ERROR_PIPE_BUSY) {
          return;
        }
        WaitNamedPipeW(name.c_str(), 1000);
      }
    }
    ~client() {
      close();
    }
    client(const client &) = delete;
    client &
    operator=(const client &) = delete;

    bool
    connected() const {
      return handle_ != INVALID_HANDLE_VALUE;
    }
    DWORD
    error() const {
      return error_;
    }
    void
    close() {
      if (handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
      }
    }

    /** Writes all of it, or gives up after the limit. */
    bool
    write(const std::string &data, std::chrono::milliseconds limit = 3s) {
      std::size_t sent = 0;
      const auto end = std::chrono::steady_clock::now() + limit;
      while (sent < data.size()) {
        OVERLAPPED ov {};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        DWORD wrote = 0;
        bool ok = WriteFile(handle_, data.data() + sent, static_cast<DWORD>(data.size() - sent), nullptr, &ov) != FALSE;
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
          const auto left = std::max<long long>(0, std::chrono::duration_cast<std::chrono::milliseconds>(end - std::chrono::steady_clock::now()).count());
          if (WaitForSingleObject(ov.hEvent, static_cast<DWORD>(left)) != WAIT_OBJECT_0) {
            CancelIoEx(handle_, &ov);
          }
          ok = GetOverlappedResult(handle_, &ov, &wrote, TRUE) != FALSE;
        }
        else if (ok) {
          GetOverlappedResult(handle_, &ov, &wrote, TRUE);
        }
        CloseHandle(ov.hEvent);
        if (!ok || wrote == 0) {
          return false;
        }
        sent += wrote;
      }
      return true;
    }

    /** Reads until a newline, end of stream or the limit. */
    std::string
    read_reply(std::chrono::milliseconds limit = 5s, bool *timed_out = nullptr) {
      std::string data;
      const auto end = std::chrono::steady_clock::now() + limit;
      if (timed_out) {
        *timed_out = false;
      }
      while (data.find('\n') == std::string::npos) {
        char buffer[4096];
        OVERLAPPED ov {};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        DWORD got = 0;
        bool ok = ReadFile(handle_, buffer, sizeof(buffer), nullptr, &ov) != FALSE;
        bool expired = false;
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
          const auto left = std::max<long long>(0, std::chrono::duration_cast<std::chrono::milliseconds>(end - std::chrono::steady_clock::now()).count());
          if (WaitForSingleObject(ov.hEvent, static_cast<DWORD>(left)) != WAIT_OBJECT_0) {
            CancelIoEx(handle_, &ov);
            expired = true;
          }
          ok = GetOverlappedResult(handle_, &ov, &got, TRUE) != FALSE;
        }
        else if (ok) {
          GetOverlappedResult(handle_, &ov, &got, TRUE);
        }
        CloseHandle(ov.hEvent);
        if (ok && got > 0) {
          data.append(buffer, got);
          continue;
        }
        if (expired && timed_out) {
          *timed_out = true;
        }
        break;
      }
      return data;
    }

  private:
    HANDLE handle_ {INVALID_HANDLE_VALUE};
    DWORD error_ {ERROR_SUCCESS};
  };

  /** Sends one request line and returns the reply line ("" when the server closed without one). */
  std::string
  ask(const std::wstring &name, const std::string &request, bool add_newline = true) {
    client c {name};
    if (!c.connected()) {
      return "<connect failed " + std::to_string(c.error()) + ">";
    }
    c.write(add_newline ? request + "\n" : request);
    return c.read_reply();
  }

  nlohmann::json
  ask_json(const std::wstring &name, const std::string &request) {
    const auto reply = ask(name, request);
    EXPECT_FALSE(reply.empty()) << "no reply to: " << request.substr(0, 80);
    EXPECT_EQ(reply.back(), '\n');
    return nlohmann::json::parse(reply, nullptr, false);
  }

  /** A pipe a test can talk to with or without elevation. */
  struct fixture {
    fake_backend backend;
    std::wstring name {unique_pipe_name()};
    std::unique_ptr<usb_control_pipe> pipe;

    bool
    start(std::function<void(usb_control_pipe_config &)> tweak = {}) {
      usb_control_pipe_config config;
      config.name = name;
      config.test_extra_allowed_sid = current_user_sid_text();
      config.test_owner_sid = current_user_sid_text();
      config.io_timeout = 1500ms;
      if (tweak) {
        tweak(config);
      }
      pipe = std::make_unique<usb_control_pipe>(backend, std::move(config));
      return pipe->start();
    }
  };

  void
  expect_error(const nlohmann::json &reply, const char *code) {
    ASSERT_TRUE(reply.is_object());
    EXPECT_EQ(reply.value("v", 0), 1);
    EXPECT_EQ(reply.value("ok", true), false);
    EXPECT_EQ(reply.value("error", std::string {}), code);
  }

  // ---- the access list of the live pipe ---------------------------------------------------------------------

  struct ace_summary {
    BYTE type;
    BYTE flags;
    DWORD mask;
    std::string sid;
  };

  std::vector<ace_summary>
  read_dacl(HANDLE pipe, bool *has_dacl) {
    std::vector<ace_summary> result;
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;
    *has_dacl = false;
    if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS) {
      return result;
    }
    *has_dacl = dacl != nullptr;
    if (dacl) {
      ACL_SIZE_INFORMATION info {};
      GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation);
      for (DWORD i = 0; i < info.AceCount; ++i) {
        void *raw = nullptr;
        GetAce(dacl, i, &raw);
        const auto *header = static_cast<ACE_HEADER *>(raw);
        const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
        LPSTR text = nullptr;
        std::string sid;
        if (ConvertSidToStringSidA(const_cast<PSID>(static_cast<const void *>(&ace->SidStart)), &text)) {
          sid = text;
          LocalFree(text);
        }
        result.push_back({header->AceType, header->AceFlags, ace->Mask, sid});
      }
    }
    LocalFree(sd);
    return result;
  }

  std::string
  sid_text(PSID sid) {
    LPSTR text = nullptr;
    std::string result;
    if (sid && ConvertSidToStringSidA(sid, &text)) {
      result = text;
      LocalFree(text);
    }
    return result;
  }

  std::string
  read_owner(HANDLE pipe) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    PSID owner = nullptr;
    std::string result;
    if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &sd) == ERROR_SUCCESS) {
      result = sid_text(owner);
      LocalFree(sd);
    }
    return result;
  }

  /** What the pipe asked Windows for, and the access list Windows reports for the first instance it made. */
  struct creation_log {
    std::mutex mutex;
    std::vector<DWORD> open_modes;
    std::vector<DWORD> pipe_modes;
    std::vector<DWORD> max_instances;
    std::vector<ace_summary> first_dacl;
    bool first_has_dacl {false};
    std::string first_owner;
  };

  usb_control_pipe_config
  logging_config(creation_log &log, const std::wstring &name) {
    usb_control_pipe_config config;
    config.name = name;
    config.io_timeout = 1500ms;
    // The production access list and owner rules. Without elevation the pipe could not be owned by SYSTEM or
    // Administrators, so the owner check alone is relaxed to the current user there.
    if (!process_is_elevated()) {
      config.test_owner_sid = current_user_sid_text();
    }
    config.create_pipe = [&log](const wchar_t *pipe_name, unsigned long open_mode, unsigned long pipe_mode, unsigned long instances, unsigned long out, unsigned long in, unsigned long timeout, void *attributes) -> void * {
      HANDLE handle = CreateNamedPipeW(pipe_name, open_mode, pipe_mode, instances, out, in, timeout, static_cast<SECURITY_ATTRIBUTES *>(attributes));
      const std::lock_guard lock {log.mutex};
      log.open_modes.push_back(open_mode);
      log.pipe_modes.push_back(pipe_mode);
      log.max_instances.push_back(instances);
      if (log.open_modes.size() == 1 && handle != INVALID_HANDLE_VALUE) {
        log.first_dacl = read_dacl(handle, &log.first_has_dacl);
        log.first_owner = read_owner(handle);
      }
      return handle;
    };
    return config;
  }

  // ---- a token that is NOT an administrator -----------------------------------------------------------------

  /**
   * An impersonation token made from this process's own token with Administrators and SYSTEM switched to
   * deny-only and every privilege removed. It is what the same user's token looks like in a standard,
   * non-elevated session, and it cannot be talked into passing an Administrators-only check. A real
   * second user account would be a stronger test but needs a password and an account on the host.
   */
  HANDLE
  make_limited_token() {
    HANDLE process_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &process_token)) {
      return nullptr;
    }
    PSID admins = nullptr;
    PSID system_sid = nullptr;
    ConvertStringSidToSidW(L"S-1-5-32-544", &admins);
    ConvertStringSidToSidW(L"S-1-5-18", &system_sid);

    DWORD size = 0;
    GetTokenInformation(process_token, TokenGroups, nullptr, 0, &size);
    std::vector<char> groups_buffer(size);
    GetTokenInformation(process_token, TokenGroups, groups_buffer.data(), size, &size);
    const auto *groups = reinterpret_cast<TOKEN_GROUPS *>(groups_buffer.data());

    std::vector<SID_AND_ATTRIBUTES> to_disable;
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
      if (EqualSid(groups->Groups[i].Sid, admins) || EqualSid(groups->Groups[i].Sid, system_sid)) {
        to_disable.push_back({groups->Groups[i].Sid, 0});
      }
    }
    // When the test itself runs as SYSTEM, the user SID is the one to disable.
    size = 0;
    GetTokenInformation(process_token, TokenUser, nullptr, 0, &size);
    std::vector<char> user_buffer(size);
    GetTokenInformation(process_token, TokenUser, user_buffer.data(), size, &size);
    const auto *user = reinterpret_cast<TOKEN_USER *>(user_buffer.data());
    if (EqualSid(user->User.Sid, system_sid)) {
      to_disable.push_back({user->User.Sid, 0});
    }

    HANDLE restricted = nullptr;
    HANDLE impersonation = nullptr;
    if (CreateRestrictedToken(process_token, DISABLE_MAX_PRIVILEGE, static_cast<DWORD>(to_disable.size()), to_disable.empty() ? nullptr : to_disable.data(), 0, nullptr, 0, nullptr, &restricted)) {
      DuplicateTokenEx(restricted, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &impersonation);
      CloseHandle(restricted);
    }
    CloseHandle(process_token);
    LocalFree(admins);
    LocalFree(system_sid);
    return impersonation;
  }

  /** An impersonation token made from this process's own token, with nothing taken away. */
  HANDLE
  make_unrestricted_token() {
    HANDLE process_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &process_token)) {
      return nullptr;
    }
    HANDLE impersonation = nullptr;
    DuplicateTokenEx(process_token, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &impersonation);
    CloseHandle(process_token);
    return impersonation;
  }

  struct open_results {
    DWORD unrestricted {0xFFFFFFFF};
    DWORD limited {0xFFFFFFFF};
  };

  /**
   * Opens the pipe twice on ONE helper thread: first impersonating the unrestricted duplicate, then the
   * limited one. Both attempts share the thread, the pipe and the moment, so a difference between them can
   * only come from the restriction. Each result is the Win32 error (0 = opened).
   */
  open_results
  open_unrestricted_and_limited(const std::wstring &name) {
    open_results results;
    HANDLE full = make_unrestricted_token();
    HANDLE limited = make_limited_token();
    if (!full || !limited) {
      results.unrestricted = results.limited = 0xFFFFFFFD;
    }
    else {
      std::thread helper([&] {
        const auto try_open = [&](HANDLE token) -> DWORD {
          if (!SetThreadToken(nullptr, token)) {
            return 0xFFFFFFFE;
          }
          HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
          const DWORD result = h == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
          if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
          }
          RevertToSelf();
          return result;
        };
        results.unrestricted = try_open(full);
        results.limited = try_open(limited);
      });
      helper.join();
    }
    if (full) {
      CloseHandle(full);
    }
    if (limited) {
      CloseHandle(limited);
    }
    return results;
  }

  /** The production access list and owner rules; without elevation only the owner rule is relaxed. */
  usb_control_pipe_config
  production_config(const std::wstring &name) {
    usb_control_pipe_config config;
    config.name = name;
    config.io_timeout = 1500ms;
    config.backoff_initial = 5ms;
    config.backoff_max = 20ms;
    if (!process_is_elevated()) {
      config.test_owner_sid = current_user_sid_text();
    }
    return config;
  }

}  // namespace

// ---- the default is off ---------------------------------------------------------------------------------------

TEST(UsbControlConfig, DefaultsToOffAndParsesLikeTheOtherSwitch) {
  const config::nvhttp_t defaults;
  EXPECT_FALSE(defaults.usb_forwarding_control);
  EXPECT_FALSE(config::nvhttp.usb_forwarding_control);
  auto vars = config::parse_config("usb_forwarding_control = enabled\n");
  EXPECT_EQ(vars.at("usb_forwarding_control"), "enabled");
}

TEST(UsbControlPipe, WithTheKeyOffNoPipeIsCreatedAndNothingIsListening) {
  fake_backend backend;
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  auto pipe = remote_usb::start_usb_control_pipe_if_enabled(false, backend, config);
  EXPECT_EQ(pipe, nullptr);

  // The name does not exist: nobody could connect, not even us.
  client probe {name};
  EXPECT_FALSE(probe.connected());
  EXPECT_EQ(probe.error(), static_cast<DWORD>(ERROR_FILE_NOT_FOUND));

  // And the same call with the key on does make one.
  pipe = remote_usb::start_usb_control_pipe_if_enabled(true, backend, config);
  ASSERT_NE(pipe, nullptr);
  client on {name};
  EXPECT_TRUE(on.connected());
}

TEST(UsbControlPipe, TheNameCarriesTheMainPort) {
  EXPECT_EQ(remote_usb::usb_control_pipe_name(47989), L"\\\\.\\pipe\\ApolloVibe-usb-control-47989");
  EXPECT_NE(remote_usb::usb_control_pipe_name(48100), remote_usb::usb_control_pipe_name(47989));
}

// ---- who can connect ------------------------------------------------------------------------------------------

TEST(UsbControlPipeSecurity, TheLivePipeListsExactlySystemAndAdministrators) {
  fake_backend backend;
  creation_log log;
  auto config = logging_config(log, unique_pipe_name());  // production: no extra entry
  usb_control_pipe pipe {backend, config};
  ASSERT_TRUE(pipe.start());

  const std::lock_guard lock {log.mutex};
  ASSERT_TRUE(log.first_has_dacl) << "a null DACL would let everyone in";
  ASSERT_EQ(log.first_dacl.size(), 2u);
  std::set<std::string> sids;
  for (const auto &ace : log.first_dacl) {
    EXPECT_EQ(ace.type, ACCESS_ALLOWED_ACE_TYPE);
    EXPECT_EQ(ace.flags, 0);
    sids.insert(ace.sid);
    GENERIC_MAPPING mapping {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    DWORD mask = ace.mask;
    MapGenericMask(&mask, &mapping);
    DWORD want = GENERIC_READ | GENERIC_WRITE;
    MapGenericMask(&want, &mapping);
    EXPECT_EQ(mask, want) << ace.sid;
  }
  EXPECT_EQ(sids, (std::set<std::string> {"S-1-5-18", "S-1-5-32-544"}));
  for (const char *forbidden : {"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4", "S-1-5-2", "S-1-5-32-546"}) {
    EXPECT_EQ(sids.count(forbidden), 0u) << forbidden << " must not be in the list";
  }
}

TEST(UsbControlPipeSecurity, RemoteClientsAreRefusedByThePipeItself) {
  fake_backend backend;
  creation_log log;
  usb_control_pipe pipe {backend, logging_config(log, unique_pipe_name())};
  ASSERT_TRUE(pipe.start());
  const std::lock_guard lock {log.mutex};
  ASSERT_FALSE(log.pipe_modes.empty());
  EXPECT_NE(log.pipe_modes[0] & PIPE_REJECT_REMOTE_CLIENTS, 0u);
  EXPECT_EQ(log.pipe_modes[0] & PIPE_ACCEPT_REMOTE_CLIENTS, 0u);
  for (const auto mode : log.pipe_modes) {
    EXPECT_NE(mode & PIPE_REJECT_REMOTE_CLIENTS, 0u) << "every instance, not only the first";
  }
}

TEST(UsbControlPipeSecurity, TheFirstInstanceFlagIsSetAndAClaimedNameFailsClosed) {
  fake_backend backend;
  creation_log log;
  usb_control_pipe pipe {backend, logging_config(log, unique_pipe_name())};
  ASSERT_TRUE(pipe.start());
  {
    const std::lock_guard lock {log.mutex};
    ASSERT_FALSE(log.open_modes.empty());
    EXPECT_NE(log.open_modes[0] & FILE_FLAG_FIRST_PIPE_INSTANCE, 0u);
  }

  // Somebody else already owns the name: we must not join it.
  const auto taken = unique_pipe_name();
  HANDLE squatter = CreateNamedPipeW(taken.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nullptr);
  ASSERT_NE(squatter, INVALID_HANDLE_VALUE);
  fake_backend other_backend;
  usb_control_pipe second {other_backend, logging_config(log, taken)};
  EXPECT_FALSE(second.start());
  EXPECT_FALSE(second.running());
  CloseHandle(squatter);
}

TEST(UsbControlPipeSecurity, TwoPipesWithTheSameNameCannotBothRun) {
  fixture f;
  ASSERT_TRUE(f.start());
  fake_backend backend2;
  usb_control_pipe_config config;
  config.name = f.name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  usb_control_pipe second {backend2, config};
  EXPECT_FALSE(second.start());
  // The first one is untouched and still answers.
  EXPECT_TRUE(ask_json(f.name, R"({"v":1,"op":"status"})").value("ok", false));
}

TEST(UsbControlPipeSecurity, AnAccessListOtherThanTheIntendedOneIsNotServed) {
  fake_backend backend;
  usb_control_pipe_config config;
  config.name = unique_pipe_name();
  // A pipe that is open to Everyone, whatever descriptor it was asked for.
  config.create_pipe = [](const wchar_t *name, unsigned long open_mode, unsigned long pipe_mode, unsigned long instances, unsigned long out, unsigned long in, unsigned long timeout, void *) -> void * {
    PSECURITY_DESCRIPTOR sd = nullptr;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;WD)", SDDL_REVISION_1, &sd, nullptr);
    SECURITY_ATTRIBUTES attributes {sizeof(attributes), sd, FALSE};
    HANDLE handle = CreateNamedPipeW(name, open_mode, pipe_mode, instances, out, in, timeout, &attributes);
    LocalFree(sd);
    return handle;
  };
  usb_control_pipe pipe {backend, config};
  EXPECT_FALSE(pipe.start());
  EXPECT_FALSE(pipe.running());
  client probe {config.name};
  EXPECT_FALSE(probe.connected()) << "the refused pipe must be closed again";
}

TEST(UsbControlPipeSecurity, ALimitedTokenIsRefusedWithAccessDenied) {
  fake_backend backend;
  const auto name = unique_pipe_name();
  usb_control_pipe pipe {backend, production_config(name)};  // the production access list: no extra entry
  ASSERT_TRUE(pipe.start());

  const auto results = open_unrestricted_and_limited(name);
  ASSERT_NE(results.limited, 0xFFFFFFFDu) << "could not build the tokens";
  ASSERT_NE(results.limited, 0xFFFFFFFEu) << "could not impersonate the limited token";
  EXPECT_EQ(results.limited, static_cast<DWORD>(ERROR_ACCESS_DENIED)) << "a standard token opened the control pipe";
  EXPECT_EQ(backend.calls(), 0u);
}

TEST(UsbControlPipeSecurity, TheSameUserUnrestrictedGetsInSoTheRefusalIsAboutTheRestriction) {
  if (!process_is_elevated()) {
    GTEST_SKIP() << "needs an elevated shell: an unelevated token is not an Administrator, so there is nobody to let in";
  }
  fake_backend backend;
  const auto name = unique_pipe_name();
  usb_control_pipe pipe {backend, production_config(name)};
  ASSERT_TRUE(pipe.start());

  // Same helper thread, same pipe, same moment: only the restriction differs.
  const auto results = open_unrestricted_and_limited(name);
  ASSERT_NE(results.limited, 0xFFFFFFFDu);
  ASSERT_NE(results.limited, 0xFFFFFFFEu);
  EXPECT_EQ(results.unrestricted, static_cast<DWORD>(ERROR_SUCCESS)) << "the unrestricted duplicate was refused too, so the test proves nothing";
  EXPECT_EQ(results.limited, static_cast<DWORD>(ERROR_ACCESS_DENIED));

  client plain {name};
  ASSERT_TRUE(plain.connected()) << plain.error();
  plain.write("{\"v\":1,\"op\":\"status\"}\n");
  EXPECT_TRUE(nlohmann::json::parse(plain.read_reply(), nullptr, false).value("ok", false));
}

TEST(UsbControlPipeSecurity, WithoutElevationNobodyOfTheSameUserGetsIn) {
  if (process_is_elevated()) {
    GTEST_SKIP() << "needs a NON-elevated shell: it checks that a standard session cannot open the pipe";
  }
  fake_backend backend;
  const auto name = unique_pipe_name();
  usb_control_pipe pipe {backend, production_config(name)};
  ASSERT_TRUE(pipe.start());
  client plain {name};
  EXPECT_FALSE(plain.connected());
  EXPECT_EQ(plain.error(), static_cast<DWORD>(ERROR_ACCESS_DENIED));
}

// ---- the protocol ---------------------------------------------------------------------------------------------

TEST(UsbControlPipeProtocol, StatusReportsTheStateAndOnlyTheDocumentedFields) {
  fixture f;
  f.backend.canned.enabled = true;
  f.backend.canned.listening = true;
  f.backend.canned.port = 47996;
  f.backend.canned.require_stream = false;
  f.backend.canned.forwards.push_back({"uuid-1", "Player One", "1-2", 1700000000});
  f.backend.canned.clients.push_back({"uuid-1", "Player One", true});
  f.backend.canned.clients.push_back({"uuid-2", "Player Two", false});
  ASSERT_TRUE(f.start());

  const auto reply = ask_json(f.name, R"({"v":1,"op":"status"})");
  ASSERT_TRUE(reply.is_object());
  EXPECT_EQ(reply["v"], 1);
  EXPECT_EQ(reply["ok"], true);
  EXPECT_EQ(reply["enabled"], true);
  EXPECT_EQ(reply["listening"], true);
  EXPECT_EQ(reply["port"], 47996);
  EXPECT_EQ(reply["require_stream"], false);
  ASSERT_EQ(reply["forwards"].size(), 1u);
  EXPECT_EQ(reply["forwards"][0]["client_uuid"], "uuid-1");
  EXPECT_EQ(reply["forwards"][0]["client_name"], "Player One");
  EXPECT_EQ(reply["forwards"][0]["busid"], "1-2");
  EXPECT_EQ(reply["forwards"][0]["since_unix"], 1700000000);
  ASSERT_EQ(reply["clients"].size(), 2u);
  EXPECT_EQ(reply["clients"][0]["usb_permission"], true);
  EXPECT_EQ(reply["clients"][1]["usb_permission"], false);
  EXPECT_FALSE(reply.contains("error"));

  std::set<std::string> keys;
  for (auto it = reply.begin(); it != reply.end(); ++it) {
    keys.insert(it.key());
  }
  EXPECT_EQ(keys, (std::set<std::string> {"v", "ok", "enabled", "listening", "port", "require_stream", "forwards", "clients", "denied"}));
}

TEST(UsbControlPipeProtocol, StatusWithInvalidUtf8InANameStillAnswers) {
  fixture f;
  f.backend.canned.clients.push_back({"uuid-1", std::string("bad\xff name"), true});
  ASSERT_TRUE(f.start());
  const auto reply = ask_json(f.name, R"({"v":1,"op":"status"})");
  ASSERT_TRUE(reply.is_object());
  EXPECT_EQ(reply["ok"], true);
}

TEST(UsbControlPipeProtocol, SetEnabledPassesTheValueAndSaysItIsNotPersisted) {
  fixture f;
  ASSERT_TRUE(f.start());

  auto reply = ask_json(f.name, R"({"v":1,"op":"set_enabled","enabled":true})");
  EXPECT_EQ(reply["ok"], true);
  EXPECT_EQ(reply["enabled"], true);
  EXPECT_EQ(reply["persisted"], false);
  reply = ask_json(f.name, R"({"v":1,"op":"set_enabled","enabled":false})");
  EXPECT_EQ(reply["ok"], true);
  EXPECT_EQ(reply["enabled"], false);

  const std::lock_guard lock {f.backend.mutex};
  ASSERT_EQ(f.backend.set_calls.size(), 2u);
  EXPECT_TRUE(f.backend.set_calls[0]);
  EXPECT_FALSE(f.backend.set_calls[1]);
}

TEST(UsbControlPipeProtocol, SetEnabledFailuresBecomeFixedCodes) {
  struct {
    remote_usb::control_error error;
    const char *code;
  } cases[] = {
    {remote_usb::control_error::port_refused, "port_refused"},
    {remote_usb::control_error::start_failed, "start_failed"},
    {remote_usb::control_error::shutting_down, "shutting_down"},
    {remote_usb::control_error::internal, "internal"},
  };
  for (const auto &c : cases) {
    fixture f;
    f.backend.set_error = c.error;
    ASSERT_TRUE(f.start());
    expect_error(ask_json(f.name, R"({"v":1,"op":"set_enabled","enabled":true})"), c.code);
  }
}

TEST(UsbControlPipeProtocol, RevokeClientCutsThatClientAndReportsTheCount) {
  fixture f;
  f.backend.revoke_result = 3;
  ASSERT_TRUE(f.start());
  const auto reply = ask_json(f.name, R"({"v":1,"op":"revoke_client","client_uuid":"3f2a-ab"})");
  EXPECT_EQ(reply["ok"], true);
  EXPECT_EQ(reply["forwards_cut"], 3);
  EXPECT_EQ(reply["denied"], true);
  const std::lock_guard lock {f.backend.mutex};
  ASSERT_EQ(f.backend.revoked.size(), 1u);
  EXPECT_EQ(f.backend.revoked[0], "3F2A-AB") << "the pipe hands the backend the canonical (upper-case) form";
  EXPECT_TRUE(f.backend.set_calls.empty()) << "revoking a client must not switch anything off";
}

TEST(UsbControlPipeProtocol, BadRequestsGetFixedCodesAndNeverReachTheBackend) {
  fixture f;
  ASSERT_TRUE(f.start());

  struct {
    std::string request;
    const char *code;
  } cases[] = {
    {"", "bad_request"},
    {"ATTACKERTEXT not json", "bad_request"},
    {"[1,2,3]", "bad_request"},
    {"\"ATTACKERTEXT\"", "bad_request"},
    {"{\"v\":1,\"op\":\"status\"", "bad_request"},
    {R"({"op":"status"})", "bad_field"},
    {R"({"v":"1","op":"status"})", "bad_field"},
    {R"({"v":1.5,"op":"status"})", "bad_field"},
    {R"({"v":true,"op":"status"})", "bad_field"},
    {R"({"v":2,"op":"status"})", "bad_version"},
    {R"({"v":0,"op":"status"})", "bad_version"},
    {R"({"v":1})", "bad_field"},
    {R"({"v":1,"op":5})", "bad_field"},
    {R"({"v":1,"op":null})", "bad_field"},
    {R"({"v":1,"op":"ATTACKERTEXT"})", "unknown_op"},
    {R"({"v":1,"op":"STATUS"})", "unknown_op"},
    {R"({"v":1,"op":"set_enabled"})", "bad_field"},
    {R"({"v":1,"op":"set_enabled","enabled":"yes"})", "bad_field"},
    {R"({"v":1,"op":"set_enabled","enabled":1})", "bad_field"},
    {R"({"v":1,"op":"revoke_client"})", "bad_field"},
    {R"({"v":1,"op":"revoke_client","client_uuid":7})", "bad_field"},
    {R"({"v":1,"op":"revoke_client","client_uuid":""})", "bad_field"},
    {R"({"v":1,"op":"revoke_client","client_uuid":"a b"})", "bad_field"},
    {R"({"v":1,"op":"revoke_client","client_uuid":"ATTACKERTEXT;rm"})", "bad_field"},
    {std::string("{\"v\":1,\"op\":\"\xff\xfe\"}"), "bad_request"},
    {std::string("{\"v\":1,\"op\":\"\xc0\x80\"}"), "bad_request"},
    {std::string("{\"v\":1,\"op\":\"\xed\xa0\x80\"}"), "bad_request"},
    {std::string("{\"v\":1,\"op\":\"\xf4\x90\x80\x80\"}"), "bad_request"},
    {std::string("{\"v\":1,\"op\":\"\xe2\x82\"}"), "bad_request"},
    {std::string(3000, '['), "bad_request"},
  };
  for (const auto &c : cases) {
    SCOPED_TRACE(c.request.substr(0, 60));
    const auto raw = ask(f.name, c.request);
    EXPECT_EQ(raw.find("ATTACKERTEXT"), std::string::npos) << "the reply repeats the request text";
    const auto reply = nlohmann::json::parse(raw, nullptr, false);
    expect_error(reply, c.code);
  }
  EXPECT_EQ(f.backend.calls(), 0u);
}

TEST(UsbControlPipeProtocol, AnExtraByteAfterTheLineOrCarriageReturnIsHandled) {
  fixture f;
  ASSERT_TRUE(f.start());
  EXPECT_TRUE(nlohmann::json::parse(ask(f.name, "{\"v\":1,\"op\":\"status\"}\r"), nullptr, false).value("ok", false));
  EXPECT_TRUE(nlohmann::json::parse(ask(f.name, "{\"v\":1,\"op\":\"status\"}\nGARBAGE-AFTER"), nullptr, false).value("ok", false));
}

TEST(UsbControlPipeProtocol, TheRequestSizeCapIs4096BytesIncludingTheNewline) {
  fixture f;
  ASSERT_TRUE(f.start());

  const std::string base = R"({"v":1,"op":"status"})";
  // Exactly 4096 bytes with the newline: accepted.
  std::string exact = base + std::string(4096 - base.size() - 1, ' ');
  EXPECT_TRUE(nlohmann::json::parse(ask(f.name, exact), nullptr, false).value("ok", false));
  // One byte more: refused, and the backend is not asked.
  const auto before = f.backend.calls();
  std::string over = base + std::string(4097 - base.size() - 1, ' ');
  expect_error(nlohmann::json::parse(ask(f.name, over), nullptr, false), "too_large");
  // A long line without any newline is cut off at the cap.
  expect_error(nlohmann::json::parse(ask(f.name, std::string(20000, 'x'), false), nullptr, false), "too_large");
  EXPECT_EQ(f.backend.calls(), before);
}

TEST(UsbControlPipeProtocol, ASilentClientIsCutOffAtTheDeadlineAndOthersAreServed) {
  fixture f;
  ASSERT_TRUE(f.start([](usb_control_pipe_config &c) { c.io_timeout = 400ms; }));

  client silent {f.name};
  ASSERT_TRUE(silent.connected());
  // While it sits there, another client is served at once.
  const auto started = std::chrono::steady_clock::now();
  EXPECT_TRUE(ask_json(f.name, R"({"v":1,"op":"status"})").value("ok", false));
  EXPECT_LT(std::chrono::steady_clock::now() - started, 300ms);

  bool timed_out = false;
  const auto reply = silent.read_reply(4s, &timed_out);
  EXPECT_FALSE(timed_out) << "the server never gave up on the silent client";
  expect_error(nlohmann::json::parse(reply, nullptr, false), "timeout");
  EXPECT_GE(std::chrono::steady_clock::now() - started, 350ms);
  EXPECT_EQ(f.backend.calls(), 1u);
}

TEST(UsbControlPipeProtocol, AClientThatLeavesInTheMiddleOfARequestCostsNothing) {
  fixture f;
  ASSERT_TRUE(f.start([](usb_control_pipe_config &c) { c.max_connections = 1; }));
  for (int i = 0; i < 5; ++i) {
    client c {f.name};
    ASSERT_TRUE(c.connected()) << "attempt " << i << " error " << c.error();
    c.write(R"({"v":1,"op":"stat)");
    c.close();
  }
  // With a cap of one, a leaked slot would make this fail for good. A slot still being freed is
  // allowed to turn the first attempts away, so try for a moment.
  bool served = false;
  for (int attempt = 0; attempt < 40 && !served; ++attempt) {
    served = ask(f.name, R"({"v":1,"op":"status"})").find("\"ok\":true") != std::string::npos;
    if (!served) {
      std::this_thread::sleep_for(25ms);
    }
  }
  EXPECT_TRUE(served) << "a slot was never given back";
  EXPECT_EQ(f.backend.status_calls.load(), 1);
}

TEST(UsbControlPipeProtocol, ConnectionsBeyondTheCapAreClosedWithoutAReplyAndTheSlotsComeBack) {
  fixture f;
  ASSERT_TRUE(f.start([](usb_control_pipe_config &c) {
    c.max_connections = 2;
    c.io_timeout = 3s;
  }));

  client a {f.name};
  client b {f.name};
  ASSERT_TRUE(a.connected());
  ASSERT_TRUE(b.connected());
  std::this_thread::sleep_for(100ms);  // both are being served now

  const auto over = ask(f.name, R"({"v":1,"op":"status"})");
  EXPECT_TRUE(over.empty() || over.rfind("<connect failed", 0) == 0) << "the third connection was served: " << over;
  EXPECT_EQ(f.backend.calls(), 0u);

  a.close();
  b.close();
  bool served = false;
  for (int i = 0; i < 40 && !served; ++i) {
    served = ask(f.name, R"({"v":1,"op":"status"})").find("\"ok\":true") != std::string::npos;
    if (!served) {
      std::this_thread::sleep_for(50ms);
    }
  }
  EXPECT_TRUE(served) << "slots were not given back";
}

TEST(UsbControlPipeProtocol, AClientThatNeverReadsTheReplyCannotHoldTheServerForever) {
  fixture f;
  for (int i = 0; i < 400; ++i) {
    f.backend.canned.clients.push_back({"uuid-" + std::to_string(i), std::string(100, 'n'), true});
  }
  ASSERT_TRUE(f.start([](usb_control_pipe_config &c) {
    c.io_timeout = 400ms;
    c.max_connections = 1;
  }));

  client stubborn {f.name};
  ASSERT_TRUE(stubborn.connected());
  stubborn.write("{\"v\":1,\"op\":\"status\"}\n");  // the reply is bigger than the pipe buffer; we never read it
  std::this_thread::sleep_for(900ms);

  // The only slot is free again.
  client next {f.name};
  ASSERT_TRUE(next.connected());
  next.write("{\"v\":1,\"op\":\"status\"}\n");
  std::string data = next.read_reply(3s);
  EXPECT_NE(data.find("\"ok\":true"), std::string::npos);
}

TEST(UsbControlPipeProtocol, RequestsFromManyClientsAtOnceAreAllAnsweredOrClosedNeverMixed) {
  fixture f;
  ASSERT_TRUE(f.start([](usb_control_pipe_config &c) { c.max_connections = 4; }));
  std::atomic<int> good {0};
  std::vector<std::thread> threads;
  for (int i = 0; i < 12; ++i) {
    threads.emplace_back([&] {
      for (int round = 0; round < 5; ++round) {
        const auto raw = ask(f.name, R"({"v":1,"op":"status"})");
        if (raw.find("\"ok\":true") != std::string::npos) {
          ++good;
        }
        else {
          EXPECT_TRUE(raw.empty() || raw.rfind("<connect failed", 0) == 0) << raw;
        }
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }
  EXPECT_GT(good.load(), 0);
}

// ---- stopping -------------------------------------------------------------------------------------------------

TEST(UsbControlPipeLifecycle, StopReturnsPromptlyEvenWithStalledClientsAndFreesTheName) {
  fixture f;
  ASSERT_TRUE(f.start([](usb_control_pipe_config &c) { c.io_timeout = 60s; }));
  client a {f.name};
  client b {f.name};
  client c {f.name};
  ASSERT_TRUE(a.connected() && b.connected() && c.connected());
  std::this_thread::sleep_for(100ms);

  const auto started = std::chrono::steady_clock::now();
  f.pipe->stop();
  EXPECT_LT(std::chrono::steady_clock::now() - started, 2s);
  EXPECT_FALSE(f.pipe->running());

  a.close();
  b.close();
  c.close();
  client after {f.name};
  EXPECT_FALSE(after.connected());
}

TEST(UsbControlPipeLifecycle, StopFromManyThreadsAndTheDestructorIsSafe) {
  auto f = std::make_unique<fixture>();
  ASSERT_TRUE(f->start());
  std::vector<std::thread> threads;
  for (int i = 0; i < 6; ++i) {
    threads.emplace_back([&] { f->pipe->stop(); });
  }
  for (auto &t : threads) {
    t.join();
  }
  f->pipe->stop();
  f.reset();  // destructor stops again
  SUCCEED();
}

TEST(UsbControlPipeLifecycle, StopCalledFromInsideARequestDoesNotDeadlock) {
  fixture f;
  ASSERT_TRUE(f.start());
  f.backend.on_status = [&] { f.pipe->stop(); };  // a handler thread asks for the stop
  const auto reply = ask(f.name, R"({"v":1,"op":"status"})");
  (void) reply;  // the answer may or may not make it out; the point is that we get here
  const auto started = std::chrono::steady_clock::now();
  f.backend.on_status = nullptr;
  f.pipe->stop();  // the owner joins
  EXPECT_LT(std::chrono::steady_clock::now() - started, 3s);
  EXPECT_FALSE(f.pipe->running());
}

TEST(UsbControlPipeLifecycle, ItCannotBeStartedTwice) {
  fixture f;
  ASSERT_TRUE(f.start());
  EXPECT_FALSE(f.pipe->start());
  EXPECT_TRUE(ask_json(f.name, R"({"v":1,"op":"status"})").value("ok", false));
}

// ---- the real backend, behind the real pipe -------------------------------------------------------------------

namespace nvhttp {
  extern crypto::cert_chain_t cert_chain;  // defined in src/nvhttp.cpp; the tests pair fake clients through it
}

namespace {

  /** A self-signed certificate in PEM form, made once. */
  const std::string &
  test_certificate_pem() {
    static const std::string pem = [] {
      EVP_PKEY *key = EVP_EC_gen("P-256");
      X509 *cert = X509_new();
      X509_set_version(cert, 2);
      ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
      X509_gmtime_adj(X509_getm_notBefore(cert), -3600);
      X509_gmtime_adj(X509_getm_notAfter(cert), 24 * 3600);
      X509_set_pubkey(cert, key);
      X509_NAME *name = X509_get_subject_name(cert);
      X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("control-pipe-test"), -1, -1, 0);
      X509_set_issuer_name(cert, name);
      X509_sign(cert, key, EVP_sha256());
      BIO *bio = BIO_new(BIO_s_mem());
      PEM_write_bio_X509(bio, cert);
      char *data = nullptr;
      const long size = BIO_get_mem_data(bio, &data);
      std::string text(data, static_cast<std::size_t>(size));
      BIO_free(bio);
      X509_free(cert);
      EVP_PKEY_free(key);
      return text;
    }();
    return pem;
  }

  /**
   * Pairs fake clients (a uuid, a name, the USB permission) in the real certificate chain for the length of
   * a test. Tests do this while no request is in flight, so nothing reads the chain at the same time.
   */
  struct paired_clients {
    void
    add(const std::string &uuid, const std::string &name = "Test Client") {
      auto client = std::make_shared<crypto::named_cert_t>();
      client->name = name;
      client->uuid = uuid;
      client->cert = test_certificate_pem();
      client->perm = crypto::PERM::_default | crypto::PERM::usb_forward;
      nvhttp::cert_chain.add(client);
    }
    ~paired_clients() {
      nvhttp::cert_chain.clear();
    }
  };

}  // namespace

namespace {

  /** Leaves the process-wide deny list empty, whatever a test did. */
  struct deny_list_guard {
    ~deny_list_guard() {
      for (const auto &uuid : nvhttp::usb_forwarding_denied_clients()) {
        nvhttp::usb_forwarding_allow_client(uuid);
      }
    }
  };

}  // namespace

TEST(UsbControlPipeBackend, StatusFromTheRealBackendNeverCarriesTheTokenOrKeyMaterial) {
  deny_list_guard guard;
  // Make sure a recognisable token exists, then look for it in everything the pipe says.
  nvhttp::usb_forwarding_rotate_token();
  const auto token = nvhttp::usb_forwarding_token();
  ASSERT_EQ(token.size(), 64u);

  auto backend = nvhttp::make_usb_control_backend();
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  usb_control_pipe pipe {*backend, config};
  ASSERT_TRUE(pipe.start());

  for (const char *request : {R"({"v":1,"op":"status"})", R"({"v":1,"op":"set_enabled","enabled":false})", R"({"v":1,"op":"revoke_client","client_uuid":"nobody"})", R"({"v":1,"op":"nonsense"})"}) {
    SCOPED_TRACE(request);
    const auto raw = ask(name, request);
    ASSERT_FALSE(raw.empty());
    EXPECT_EQ(raw.find(token), std::string::npos) << "the tunnel token leaked";
    for (const char *secret : {"token", "BEGIN", "PRIVATE KEY", "CERTIFICATE", "pin", "pkey"}) {
      EXPECT_EQ(raw.find(secret), std::string::npos) << secret;
    }
  }

  const auto status = ask_json(name, R"({"v":1,"op":"status"})");
  EXPECT_EQ(status["ok"], true);
  EXPECT_EQ(status["enabled"], false);
  EXPECT_EQ(status["listening"], false);
  EXPECT_EQ(status["port"], 0);
  EXPECT_TRUE(status["forwards"].empty());
}

TEST(UsbControlPipeBackend, TheRealBackendRefusesToStartATunnelItCannotStartAndStaysOff) {
  deny_list_guard guard;
  // The test environment has no certificate, so the tunnel cannot start; nothing is bound or attached.
  auto backend = nvhttp::make_usb_control_backend();
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  usb_control_pipe pipe {*backend, config};
  ASSERT_TRUE(pipe.start());

  const auto reply = ask_json(name, R"({"v":1,"op":"set_enabled","enabled":true})");
  expect_error(reply, "start_failed");
  const auto status = ask_json(name, R"({"v":1,"op":"status"})");
  EXPECT_EQ(status["listening"], false);
  EXPECT_EQ(status["port"], 0);

  // Switching off something that is off is fine and says so.
  const auto off = ask_json(name, R"({"v":1,"op":"set_enabled","enabled":false})");
  EXPECT_EQ(off["ok"], true);
  EXPECT_EQ(off["persisted"], false);
  EXPECT_EQ(ask_json(name, R"({"v":1,"op":"revoke_client","client_uuid":"nobody"})")["forwards_cut"], 0);
}

// ---- the pipe in front of the real tunnel manager, with a fake tunnel -----------------------------------------

namespace {

  struct counted_tunnel final: remote_usb::tunnel_instance {
    explicit counted_tunnel(std::atomic<int> &live, std::atomic<int> &max_live, std::atomic<int> &created, std::vector<std::string> &revoked, std::mutex &revoked_mutex):
        live_(live),
        revoked_(revoked),
        revoked_mutex_(revoked_mutex) {
      const int now = ++live_;
      int seen = max_live.load();
      while (now > seen && !max_live.compare_exchange_weak(seen, now)) {
      }
      ++created;
    }
    bool
    running() const override {
      return !stopped_;
    }
    std::uint16_t
    port() const override {
      return 48100;
    }
    void
    stop() noexcept override {
      if (!stopped_.exchange(true)) {
        --live_;
      }
    }
    void
    revoke(const std::string &id) override {
      (void) revoke_counted(id);
    }
    std::optional<std::size_t>
    revoke_counted(const std::string &id) override {
      const std::lock_guard lock {revoked_mutex_};
      revoked_.push_back(id);
      return id == "CLIENT-A" ? 1 : 0;
    }
    std::optional<std::vector<remote_usb::forward_info>>
    forwards() override {
      return std::vector<remote_usb::forward_info> {{"client-a", "1-2", 5}};
    }
    std::atomic<int> &live_;
    std::vector<std::string> &revoked_;
    std::mutex &revoked_mutex_;
    std::atomic<bool> stopped_ {false};
  };

  /** The production control backend's shape, over a manager with fake tunnels. */
  class manager_backend final: public usb_control_backend {
  public:
    manager_backend():
        manager([this](remote_usb::start_failure &) -> std::shared_ptr<remote_usb::tunnel_instance> {
          return std::make_shared<counted_tunnel>(live, max_live, created, revoked, revoked_mutex);
        }) {}
    control_status
    status() override {
      control_status s;
      s.enabled = manager.enabled();
      s.listening = manager.running();
      s.port = manager.port();
      for (const auto &f : manager.forwards()) {
        s.forwards.push_back({f.client_id, "n", f.busid, f.since_unix});
      }
      return s;
    }
    remote_usb::set_enabled_outcome
    set_enabled(bool enabled) override {
      const auto result = enabled ? manager.enable() : manager.disable();
      return {result == remote_usb::manager_result::ok ? remote_usb::control_error::none : remote_usb::control_error::shutting_down, false};
    }
    remote_usb::revoke_outcome
    revoke_client(const std::string &id) override {
      return {remote_usb::control_error::none, manager.revoke_counted(id)};
    }
    remote_usb::clear_outcome
    clear_revoke(const std::string &) override {
      return {};
    }

    std::atomic<int> live {0}, max_live {0}, created {0};
    std::vector<std::string> revoked;
    std::mutex revoked_mutex;
    remote_usb::usb_tunnel_manager manager;
  };

}  // namespace

TEST(UsbControlPipeManager, StartStopStartLiveThroughThePipe) {
  manager_backend backend;
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  usb_control_pipe pipe {backend, config};
  ASSERT_TRUE(pipe.start());

  auto reply = ask_json(name, R"({"v":1,"op":"set_enabled","enabled":true})");
  EXPECT_EQ(reply["listening"], true);
  EXPECT_EQ(reply["port"], 48100);
  EXPECT_EQ(ask_json(name, R"({"v":1,"op":"status"})")["forwards"].size(), 1u);

  reply = ask_json(name, R"({"v":1,"op":"set_enabled","enabled":false})");
  EXPECT_EQ(reply["listening"], false);
  EXPECT_EQ(backend.live.load(), 0);
  EXPECT_TRUE(ask_json(name, R"({"v":1,"op":"status"})")["forwards"].empty());

  reply = ask_json(name, R"({"v":1,"op":"set_enabled","enabled":true})");
  EXPECT_EQ(reply["listening"], true);
  EXPECT_EQ(backend.created.load(), 2);
  EXPECT_EQ(backend.live.load(), 1);
}

TEST(UsbControlPipeManager, ConcurrentSetEnabledCallsNeverRunTwoTunnels) {
  manager_backend backend;
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  config.max_connections = 4;
  usb_control_pipe pipe {backend, config};
  ASSERT_TRUE(pipe.start());

  std::vector<std::thread> threads;
  for (int t = 0; t < 4; ++t) {
    threads.emplace_back([&, t] {
      for (int i = 0; i < 15; ++i) {
        ask(name, ((i + t) % 2 == 0) ? R"({"v":1,"op":"set_enabled","enabled":true})" : R"({"v":1,"op":"set_enabled","enabled":false})");
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }
  EXPECT_EQ(backend.max_live.load(), 1);
  EXPECT_EQ(backend.live.load(), backend.manager.running() ? 1 : 0);
  ask(name, R"({"v":1,"op":"set_enabled","enabled":false})");
  EXPECT_EQ(backend.live.load(), 0);
}

TEST(UsbControlPipeManager, SetEnabledRacingAShutdownEndsWithNothingRunning) {
  manager_backend backend;
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  usb_control_pipe pipe {backend, config};
  ASSERT_TRUE(pipe.start());

  std::thread asker([&] {
    for (int i = 0; i < 30; ++i) {
      ask(name, R"({"v":1,"op":"set_enabled","enabled":true})");
    }
  });
  std::this_thread::sleep_for(30ms);
  backend.manager.shutdown();
  asker.join();
  EXPECT_EQ(backend.live.load(), 0) << "a set_enabled slipped in after the shutdown";
  expect_error(ask_json(name, R"({"v":1,"op":"set_enabled","enabled":true})"), "shutting_down");
}

TEST(UsbControlPipeManager, RevokeClientDetachesOnlyThatClientThroughThePipe) {
  manager_backend backend;
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  usb_control_pipe pipe {backend, config};
  ASSERT_TRUE(pipe.start());
  ask_json(name, R"({"v":1,"op":"set_enabled","enabled":true})");

  EXPECT_EQ(ask_json(name, R"({"v":1,"op":"revoke_client","client_uuid":"client-a"})")["forwards_cut"], 1);
  EXPECT_EQ(ask_json(name, R"({"v":1,"op":"revoke_client","client_uuid":"client-b"})")["forwards_cut"], 0);
  {
    const std::lock_guard lock {backend.revoked_mutex};
    ASSERT_EQ(backend.revoked.size(), 2u);
    EXPECT_EQ(backend.revoked[0], "CLIENT-A");
    EXPECT_EQ(backend.revoked[1], "CLIENT-B");
  }
  // Revoking is not unpairing and not switching off.
  EXPECT_TRUE(backend.manager.running());
  EXPECT_EQ(backend.live.load(), 1);
}


// ---- the owner of the pipe ------------------------------------------------------------------------------------

namespace {

  std::size_t
  log_size() {
    logging::log_flush();
    std::ifstream input("test_sunshine.log", std::ios::binary | std::ios::ate);
    return input ? static_cast<std::size_t>(input.tellg()) : 0;
  }

  /** Everything logged after @p start. */
  std::string
  log_since(std::size_t start) {
    logging::log_flush();
    std::ifstream input("test_sunshine.log", std::ios::binary);
    input.seekg(static_cast<std::streamoff>(start));
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  }

  using create_hook = decltype(usb_control_pipe_config::create_pipe);

  /** A creator that cannot give the pipe an owner: every call that names one fails the way Windows does. */
  create_hook
  owner_refusing_creator() {
    return [](const wchar_t *name, unsigned long open_mode, unsigned long pipe_mode, unsigned long instances, unsigned long out, unsigned long in, unsigned long timeout, void *attributes) -> void * {
      const auto *sa = static_cast<SECURITY_ATTRIBUTES *>(attributes);
      PSID owner = nullptr;
      BOOL defaulted = FALSE;
      if (sa && sa->lpSecurityDescriptor && GetSecurityDescriptorOwner(sa->lpSecurityDescriptor, &owner, &defaulted) && owner) {
        SetLastError(ERROR_INVALID_OWNER);
        return INVALID_HANDLE_VALUE;
      }
      return CreateNamedPipeW(name, open_mode, pipe_mode, instances, out, in, timeout, const_cast<SECURITY_ATTRIBUTES *>(sa));
    };
  }

  bool
  running_as_system() {
    return current_user_sid_text() == L"S-1-5-18";
  }

}  // namespace

TEST(UsbControlPipeOwner, WhenSystemOrAdministratorsCannotOwnItThereIsNoPipeAndNoFallback) {
  fake_backend backend;
  usb_control_pipe_config config;  // production: no test owner
  config.name = unique_pipe_name();
  config.create_pipe = owner_refusing_creator();
  const auto mark = log_size();
  usb_control_pipe pipe {backend, config};
  EXPECT_FALSE(pipe.start());
  EXPECT_FALSE(pipe.running());
  EXPECT_NE(log_since(mark).find("cannot make SYSTEM or Administrators the owner"), std::string::npos);

  client probe {config.name};
  EXPECT_FALSE(probe.connected()) << "a pipe owned by the creating user was left behind";
  EXPECT_EQ(probe.error(), static_cast<DWORD>(ERROR_FILE_NOT_FOUND));
}

TEST(UsbControlPipeOwner, TheLivePipeIsOwnedBySystemOrAdministrators) {
  if (!process_is_elevated()) {
    GTEST_SKIP() << "needs an elevated shell: a standard user cannot make SYSTEM or Administrators the owner";
  }
  fake_backend backend;
  creation_log log;
  usb_control_pipe pipe {backend, logging_config(log, unique_pipe_name())};
  ASSERT_TRUE(pipe.start());
  const std::lock_guard lock {log.mutex};
  EXPECT_TRUE(log.first_owner == "S-1-5-18" || log.first_owner == "S-1-5-32-544") << "owner is " << log.first_owner;
}

TEST(UsbControlPipeOwner, APipeWithTheRightAccessListButAnotherOwnerIsNotServed) {
  if (running_as_system()) {
    GTEST_SKIP() << "the current user is SYSTEM, so it cannot stand in for another owner";
  }
  fake_backend backend;
  usb_control_pipe_config config;  // production owner rule
  config.name = unique_pipe_name();
  const std::wstring user = current_user_sid_text();
  config.create_pipe = [user](const wchar_t *name, unsigned long open_mode, unsigned long pipe_mode, unsigned long instances, unsigned long out, unsigned long in, unsigned long timeout, void *) -> void * {
    // The intended access list, but the pipe belongs to the user who made it.
    PSECURITY_DESCRIPTOR sd = nullptr;
    const std::wstring text = L"O:" + user + L"D:P(A;;GRGW;;;SY)(A;;GRGW;;;BA)";
    ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(), SDDL_REVISION_1, &sd, nullptr);
    SECURITY_ATTRIBUTES attributes {sizeof(attributes), sd, FALSE};
    HANDLE handle = CreateNamedPipeW(name, open_mode, pipe_mode, instances, out, in, timeout, &attributes);
    LocalFree(sd);
    return handle;
  };
  const auto mark = log_size();
  usb_control_pipe pipe {backend, config};
  EXPECT_FALSE(pipe.start());
  EXPECT_NE(log_since(mark).find("intended owner and access list"), std::string::npos);
  client probe {config.name};
  EXPECT_FALSE(probe.connected());
}

// ---- what a correct client checks -----------------------------------------------------------------------------

namespace {

  /** The three checks of the client contract, in the order the contract lists them. Empty = the server is acceptable. */
  std::string
  server_identity_problem(HANDLE pipe, DWORD expected_server_pid) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    PSID owner = nullptr;
    if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &sd) != ERROR_SUCCESS || !owner) {
      return "owner unreadable";
    }
    const auto owner_text = sid_text(owner);
    LocalFree(sd);
    if (owner_text != "S-1-5-18" && owner_text != "S-1-5-32-544") {
      return "owner is " + owner_text;
    }
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid)) {
      return "server pid unreadable";
    }
    if (pid != expected_server_pid) {
      return "server pid is " + std::to_string(pid);
    }
    return {};
  }

  /** Opens the pipe the way the contract demands: identification level, so the server cannot act as the client. */
  HANDLE
  open_with_identification(const std::wstring &name) {
    return CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
  }

  std::string
  blocking_exchange(HANDLE pipe, const std::string &request) {
    DWORD done = 0;
    if (!WriteFile(pipe, request.data(), static_cast<DWORD>(request.size()), &done, nullptr)) {
      return {};
    }
    std::string reply;
    char buffer[4096];
    while (reply.find('\n') == std::string::npos && ReadFile(pipe, buffer, sizeof(buffer), &done, nullptr) && done > 0) {
      reply.append(buffer, done);
    }
    return reply;
  }

  /** A pipe made by an ordinary user with the same name, open to everyone, as an impostor would make it. */
  HANDLE
  make_impostor(const std::wstring &name) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    const std::wstring text = L"O:" + current_user_sid_text() + L"D:(A;;GA;;;WD)";
    ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(), SDDL_REVISION_1, &sd, nullptr);
    SECURITY_ATTRIBUTES attributes {sizeof(attributes), sd, FALSE};
    HANDLE handle = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &attributes);
    LocalFree(sd);
    return handle;
  }

}  // namespace

TEST(UsbControlPipeClientContract, AnIdentificationLevelOpenKeepsTheServerFromActingAsTheClient) {
  // A plain pipe: the point is what the open flags do, not Apollo.
  const auto name = unique_pipe_name();
  const auto level_seen_by_server = [&](bool identification) -> int {
    HANDLE server = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
    if (server == INVALID_HANDLE_VALUE) {
      return -3;
    }
    HANDLE c = identification ? open_with_identification(name) : CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (c == INVALID_HANDLE_VALUE) {
      return -1;
    }
    ConnectNamedPipe(server, nullptr);  // already connected: ERROR_PIPE_CONNECTED
    DWORD done = 0;
    char byte = 'x';
    WriteFile(c, &byte, 1, &done, nullptr);
    ReadFile(server, &byte, 1, &done, nullptr);
    int level = -2;
    if (ImpersonateNamedPipeClient(server)) {
      HANDLE token = nullptr;
      if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        SECURITY_IMPERSONATION_LEVEL value = SecurityAnonymous;
        DWORD size = 0;
        if (GetTokenInformation(token, TokenImpersonationLevel, &value, sizeof(value), &size)) {
          level = static_cast<int>(value);
        }
        CloseHandle(token);
      }
      RevertToSelf();
    }
    DisconnectNamedPipe(server);
    CloseHandle(c);
    CloseHandle(server);
    return level;
  };

  EXPECT_EQ(level_seen_by_server(true), static_cast<int>(SecurityIdentification));
  EXPECT_GE(level_seen_by_server(false), static_cast<int>(SecurityImpersonation)) << "the control: without the flags the server could act as the client";
}

TEST(UsbControlPipeClientContract, ACorrectClientAcceptsTheRealPipeAndTalksToIt) {
  if (!process_is_elevated()) {
    GTEST_SKIP() << "needs an elevated shell: only then can Apollo own the pipe as SYSTEM or Administrators";
  }
  fake_backend backend;
  const auto name = unique_pipe_name();
  usb_control_pipe pipe {backend, production_config(name)};
  ASSERT_TRUE(pipe.start());

  HANDLE handle = open_with_identification(name);
  ASSERT_NE(handle, INVALID_HANDLE_VALUE) << GetLastError();
  EXPECT_EQ(server_identity_problem(handle, GetCurrentProcessId()), "");
  const auto reply = nlohmann::json::parse(blocking_exchange(handle, "{\"v\":1,\"op\":\"status\"}\n"), nullptr, false);
  EXPECT_TRUE(reply.value("ok", false));
  CloseHandle(handle);
}

TEST(UsbControlPipeClientContract, ACorrectClientRefusesAServerThatIsNotTheApolloItExpects) {
  if (!process_is_elevated()) {
    GTEST_SKIP() << "needs an elevated shell: only then can Apollo own the pipe as SYSTEM or Administrators";
  }
  fake_backend backend;
  const auto name = unique_pipe_name();
  usb_control_pipe pipe {backend, production_config(name)};
  ASSERT_TRUE(pipe.start());
  HANDLE handle = open_with_identification(name);
  ASSERT_NE(handle, INVALID_HANDLE_VALUE);
  // Owner and access list are right, but the client expects another process to be the Apollo.
  const auto problem = server_identity_problem(handle, GetCurrentProcessId() + 4);
  EXPECT_NE(problem.find("server pid is"), std::string::npos) << problem;
  CloseHandle(handle);
}

TEST(UsbControlPipeClientContract, AnImpostorThatTookTheNameFirstIsRefusedByApolloAndSpottedByTheClient) {
  if (running_as_system()) {
    GTEST_SKIP() << "the current user is SYSTEM, so it cannot stand in for an ordinary user";
  }
  const auto name = unique_pipe_name();
  HANDLE impostor = make_impostor(name);
  ASSERT_NE(impostor, INVALID_HANDLE_VALUE);

  // Apollo fails closed, with a line that says why.
  fake_backend backend;
  const auto mark = log_size();
  usb_control_pipe pipe {backend, production_config(name)};
  EXPECT_FALSE(pipe.start());
  EXPECT_NE(log_since(mark).find("the pipe name is already in use"), std::string::npos);

  // A client following the contract sees through it: the owner is an ordinary user.
  HANDLE handle = open_with_identification(name);
  ASSERT_NE(handle, INVALID_HANDLE_VALUE);
  const auto problem = server_identity_problem(handle, GetCurrentProcessId());
  EXPECT_NE(problem.find("owner is"), std::string::npos) << problem;
  EXPECT_EQ(backend.calls(), 0u) << "nothing real can have answered";
  CloseHandle(handle);
  CloseHandle(impostor);
}

// ---- the pipe keeps its name ----------------------------------------------------------------------------------

namespace {

  /** Forwards to the real CreateNamedPipeW, except for the calls @p fail_calls lists (1-based; call 1 is the first instance). */
  create_hook
  flaky_creator(std::shared_ptr<std::atomic<int>> calls, std::set<int> fail_calls, std::set<int> wrong_acl_calls = {}) {
    return [calls, fail_calls, wrong_acl_calls](const wchar_t *name, unsigned long open_mode, unsigned long pipe_mode, unsigned long instances, unsigned long out, unsigned long in, unsigned long timeout, void *attributes) -> void * {
      const int n = ++(*calls);
      if (fail_calls.count(n) || (fail_calls.count(-1) && n > 1)) {
        SetLastError(ERROR_PIPE_BUSY);
        return INVALID_HANDLE_VALUE;
      }
      if (wrong_acl_calls.count(n)) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;WD)", SDDL_REVISION_1, &sd, nullptr);
        SECURITY_ATTRIBUTES lax {sizeof(lax), sd, FALSE};
        HANDLE handle = CreateNamedPipeW(name, open_mode, pipe_mode, instances, out, in, timeout, &lax);
        LocalFree(sd);
        return handle;
      }
      return CreateNamedPipeW(name, open_mode, pipe_mode, instances, out, in, timeout, static_cast<SECURITY_ATTRIBUTES *>(attributes));
    };
  }

  bool
  served_within(const std::wstring &name, std::chrono::milliseconds limit, bool *name_vanished = nullptr) {
    const auto end = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < end) {
      const auto raw = ask(name, R"({"v":1,"op":"status"})");
      if (raw.rfind("<connect failed", 0) == 0 && name_vanished) {
        *name_vanished = true;
      }
      if (raw.find("\"ok\":true") != std::string::npos) {
        return true;
      }
      std::this_thread::sleep_for(10ms);
    }
    return false;
  }

}  // namespace

TEST(UsbControlPipeResilience, AFailedReplacementInstanceIsRetriedAndTheNameIsNeverFree) {
  fixture f;
  auto calls = std::make_shared<std::atomic<int>>(0);
  ASSERT_TRUE(f.start([&](usb_control_pipe_config &c) {
    c.create_pipe = flaky_creator(calls, {2, 3});  // the next two instances cannot be made
    c.backoff_initial = 5ms;
    c.backoff_max = 20ms;
  }));
  bool vanished = false;
  EXPECT_TRUE(served_within(f.name, 3s, &vanished)) << "the pipe never recovered";
  EXPECT_FALSE(vanished) << "the pipe name was free at some moment";
  EXPECT_GE(calls->load(), 4);
  EXPECT_TRUE(f.pipe->running());
}

TEST(UsbControlPipeResilience, AnInstanceThatFailsTheCheckIsClosedReplacedAndNeverServed) {
  fixture f;
  auto calls = std::make_shared<std::atomic<int>>(0);
  const auto mark = log_size();
  ASSERT_TRUE(f.start([&](usb_control_pipe_config &c) {
    c.create_pipe = flaky_creator(calls, {});
    c.test_fail_verification = [](unsigned n) { return n == 2; };  // the first replacement fails its check
    c.backoff_initial = 5ms;
    c.backoff_max = 20ms;
  }));
  bool vanished = false;
  EXPECT_TRUE(served_within(f.name, 3s, &vanished));
  EXPECT_FALSE(vanished);
  EXPECT_GE(calls->load(), 3);
  EXPECT_NE(log_since(mark).find("refused a new instance"), std::string::npos);
  EXPECT_TRUE(f.pipe->running());
  // Only the one good request was ever handled; nothing reached the backend through the bad instance.
  EXPECT_EQ(f.backend.status_calls.load(), 1);
}

TEST(UsbControlPipeResilience, StopReturnsPromptlyWhileItIsBackingOff) {
  fixture f;
  auto calls = std::make_shared<std::atomic<int>>(0);
  ASSERT_TRUE(f.start([&](usb_control_pipe_config &c) {
    c.create_pipe = flaky_creator(calls, {-1});  // no instance after the first can ever be made
    c.backoff_initial = 20s;
    c.backoff_max = 20s;
  }));
  client trigger {f.name};  // takes the first instance, so the loop has to make another and fails
  ASSERT_TRUE(trigger.connected());
  const auto limit = std::chrono::steady_clock::now() + 2s;
  while (calls->load() < 2 && std::chrono::steady_clock::now() < limit) {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_GE(calls->load(), 2);

  const auto started = std::chrono::steady_clock::now();
  f.pipe->stop();
  EXPECT_LT(std::chrono::steady_clock::now() - started, 2s);
}

// ---- revoke and the deny list ---------------------------------------------------------------------------------

TEST(UsbControlPipeProtocol, ClearRevokePassesTheClientAndSaysItIsNoLongerDenied) {
  fixture f;
  ASSERT_TRUE(f.start());
  const auto reply = ask_json(f.name, R"({"v":1,"op":"clear_revoke","client_uuid":"3f2a-ab"})");
  EXPECT_EQ(reply["ok"], true);
  EXPECT_EQ(reply["denied"], false);
  const std::lock_guard lock {f.backend.mutex};
  ASSERT_EQ(f.backend.cleared.size(), 1u);
  EXPECT_EQ(f.backend.cleared[0], "3F2A-AB");
  EXPECT_TRUE(f.backend.set_calls.empty());
}

TEST(UsbControlPipeProtocol, ClearRevokeNeedsAWellFormedUuid) {
  fixture f;
  ASSERT_TRUE(f.start());
  for (const char *request : {R"({"v":1,"op":"clear_revoke"})", R"({"v":1,"op":"clear_revoke","client_uuid":5})", R"({"v":1,"op":"clear_revoke","client_uuid":""})", R"({"v":1,"op":"clear_revoke","client_uuid":"a;b"})"}) {
    SCOPED_TRACE(request);
    expect_error(ask_json(f.name, request), "bad_field");
  }
  EXPECT_EQ(f.backend.calls(), 0u);
  EXPECT_TRUE(f.backend.cleared.empty());
}

TEST(UsbControlPipeProtocol, StatusListsTheDeniedClients) {
  fixture f;
  f.backend.canned.denied = {"u-1", "u-2"};
  ASSERT_TRUE(f.start());
  const auto reply = ask_json(f.name, R"({"v":1,"op":"status"})");
  ASSERT_EQ(reply["denied"].size(), 2u);
  EXPECT_EQ(reply["denied"][0], "u-1");
  EXPECT_EQ(reply["denied"][1], "u-2");
}

TEST(UsbControlPipeProtocol, AFullDenyListIsReportedByAFixedCode) {
  fixture f;
  f.backend.revoke_error = remote_usb::control_error::deny_list_full;
  ASSERT_TRUE(f.start());
  expect_error(ask_json(f.name, R"({"v":1,"op":"revoke_client","client_uuid":"u-1"})"), "deny_list_full");
}

TEST(UsbControlPipeBackend, RevokeDeniesTheClientListsItAndClearRevokeTakesItBack) {
  deny_list_guard guard;
  auto backend = nvhttp::make_usb_control_backend();
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  usb_control_pipe pipe {*backend, config};
  ASSERT_TRUE(pipe.start());

  const auto revoked = ask_json(name, R"({"v":1,"op":"revoke_client","client_uuid":"real-1"})");
  EXPECT_EQ(revoked["ok"], true);
  EXPECT_EQ(revoked["forwards_cut"], 0);
  EXPECT_EQ(revoked["denied"], true);
  EXPECT_TRUE(nvhttp::usb_forwarding_client_denied("real-1"));
  EXPECT_FALSE(nvhttp::usb_forwarding_client_denied("real-2"));

  const auto status = ask_json(name, R"({"v":1,"op":"status"})");
  ASSERT_EQ(status["denied"].size(), 1u);
  EXPECT_EQ(status["denied"][0], "REAL-1");

  EXPECT_EQ(ask_json(name, R"({"v":1,"op":"clear_revoke","client_uuid":"real-1"})")["denied"], false);
  EXPECT_FALSE(nvhttp::usb_forwarding_client_denied("real-1"));
  EXPECT_TRUE(ask_json(name, R"({"v":1,"op":"status"})")["denied"].empty());
}

TEST(UsbControlPipeBackend, TheDenyListIsBoundedAndSaysSoWhenFullOfPairedClients) {
  deny_list_guard guard;
  paired_clients paired;
  for (std::size_t i = 0; i < nvhttp::USB_FORWARDING_MAX_DENIED; ++i) {
    paired.add("BULK-" + std::to_string(i));
    ASSERT_EQ(nvhttp::usb_forwarding_deny_client("bulk-" + std::to_string(i)), nvhttp::usb_deny_result::added);
  }
  // Every entry belongs to a paired client, so nothing can be dropped to make room.
  EXPECT_EQ(nvhttp::usb_forwarding_deny_client("one-too-many"), nvhttp::usb_deny_result::full);
  EXPECT_EQ(nvhttp::usb_forwarding_deny_client("bulk-0"), nvhttp::usb_deny_result::already_denied) << "a client already on the list is not 'full'";
  EXPECT_FALSE(nvhttp::usb_forwarding_client_denied("one-too-many"));

  auto backend = nvhttp::make_usb_control_backend();
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  usb_control_pipe pipe {*backend, config};
  ASSERT_TRUE(pipe.start());
  expect_error(ask_json(name, R"({"v":1,"op":"revoke_client","client_uuid":"one-too-many"})"), "deny_list_full");
  EXPECT_EQ(nvhttp::usb_forwarding_denied_clients().size(), nvhttp::USB_FORWARDING_MAX_DENIED);
}

TEST(UsbControlPipeBackend, AFullDenyListFirstForgetsClientsThatAreNoLongerPaired) {
  deny_list_guard guard;
  paired_clients paired;
  paired.add("KEEP-ME");
  ASSERT_EQ(nvhttp::usb_forwarding_deny_client("keep-me"), nvhttp::usb_deny_result::added);
  for (std::size_t i = 0; i + 1 < nvhttp::USB_FORWARDING_MAX_DENIED; ++i) {
    ASSERT_EQ(nvhttp::usb_forwarding_deny_client("gone-" + std::to_string(i)), nvhttp::usb_deny_result::added);  // nobody is paired under these
  }
  ASSERT_EQ(nvhttp::usb_forwarding_denied_clients().size(), nvhttp::USB_FORWARDING_MAX_DENIED);

  EXPECT_EQ(nvhttp::usb_forwarding_deny_client("new-one"), nvhttp::usb_deny_result::added);
  EXPECT_TRUE(nvhttp::usb_forwarding_client_denied("NEW-ONE"));
  EXPECT_TRUE(nvhttp::usb_forwarding_client_denied("keep-me")) << "a paired client's deny was dropped";
  EXPECT_FALSE(nvhttp::usb_forwarding_client_denied("gone-0"));
  EXPECT_EQ(nvhttp::usb_forwarding_denied_clients().size(), 2u);
}

TEST(UsbControlPipeBackend, RevokeFindsTheRealClientWhateverTheCaseAndReportsIt) {
  deny_list_guard guard;
  paired_clients paired;
  paired.add("AB12CD34-0000-4000-8000-0000000000EF", "Player One");
  auto backend = nvhttp::make_usb_control_backend();
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  usb_control_pipe pipe {*backend, config};
  ASSERT_TRUE(pipe.start());

  for (const char *typed : {"ab12cd34-0000-4000-8000-0000000000ef", "AB12CD34-0000-4000-8000-0000000000EF", "Ab12Cd34-0000-4000-8000-0000000000eF"}) {
    SCOPED_TRACE(typed);
    const auto revoked = ask_json(name, std::string(R"({"v":1,"op":"revoke_client","client_uuid":")") + typed + R"("})");
    EXPECT_EQ(revoked["ok"], true);
    EXPECT_EQ(revoked["denied"], true);
    EXPECT_EQ(revoked["known"], true);
    EXPECT_TRUE(nvhttp::usb_forwarding_client_denied("AB12CD34-0000-4000-8000-0000000000EF")) << "the real client was not denied";
    EXPECT_EQ(nvhttp::usb_forwarding_denied_clients().size(), 1u) << "a second spelling made a second entry";

    const auto cleared = ask_json(name, std::string(R"({"v":1,"op":"clear_revoke","client_uuid":")") + typed + R"("})");
    EXPECT_EQ(cleared["denied"], false);
    EXPECT_EQ(cleared["known"], true);
    EXPECT_FALSE(nvhttp::usb_forwarding_client_denied("AB12CD34-0000-4000-8000-0000000000EF")) << "clear_revoke missed the real client";
  }
}

TEST(UsbControlPipeBackend, AnUnknownUuidIsStillDeniedButTheReplySaysKnownFalse) {
  deny_list_guard guard;
  paired_clients paired;
  paired.add("REAL-CLIENT");
  auto backend = nvhttp::make_usb_control_backend();
  const auto name = unique_pipe_name();
  usb_control_pipe_config config;
  config.name = name;
  config.test_extra_allowed_sid = current_user_sid_text();
  config.test_owner_sid = current_user_sid_text();
  usb_control_pipe pipe {*backend, config};
  ASSERT_TRUE(pipe.start());

  const auto typo = ask_json(name, R"({"v":1,"op":"revoke_client","client_uuid":"real-clent"})");
  EXPECT_EQ(typo["ok"], true);
  EXPECT_EQ(typo["denied"], true);
  EXPECT_EQ(typo["known"], false) << "a typo looked like a success";
  EXPECT_TRUE(nvhttp::usb_forwarding_client_denied("REAL-CLENT"));
  EXPECT_FALSE(nvhttp::usb_forwarding_client_denied("REAL-CLIENT"));
  EXPECT_EQ(ask_json(name, R"({"v":1,"op":"clear_revoke","client_uuid":"real-clent"})")["known"], false);
}

// ---- nvhttp wiring --------------------------------------------------------------------------------------------

TEST(UsbControlNvhttp, WithTheKeyOffStartingThroughNvhttpCreatesNoPipe) {
  ASSERT_FALSE(config::nvhttp.usb_forwarding_control);
  fake_backend backend;
  usb_control_pipe_config base;
  base.name = unique_pipe_name();
  base.test_extra_allowed_sid = current_user_sid_text();
  base.test_owner_sid = current_user_sid_text();
  EXPECT_EQ(nvhttp::start_usb_control(backend, base), nullptr);
  client probe {base.name};
  EXPECT_FALSE(probe.connected());
  EXPECT_EQ(probe.error(), static_cast<DWORD>(ERROR_FILE_NOT_FOUND));

  config::nvhttp.usb_forwarding_control = true;
  auto on = nvhttp::start_usb_control(backend, base);
  config::nvhttp.usb_forwarding_control = false;
  ASSERT_NE(on, nullptr);
  client probe_on {base.name};
  EXPECT_TRUE(probe_on.connected());
}

TEST(UsbControlNvhttp, EveryTunnelStartGetsANewTokenAndABadPortIsRefused) {
  remote_usb::start_failure failure = remote_usb::start_failure::none;
  const auto first = nvhttp::make_usb_tunnel_config(failure);
  ASSERT_TRUE(first.has_value());
  const auto token_one = nvhttp::usb_forwarding_token();
  EXPECT_EQ(first->session_token, token_one);

  const auto second = nvhttp::make_usb_tunnel_config(failure);
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(second->session_token, nvhttp::usb_forwarding_token());
  EXPECT_NE(second->session_token, token_one) << "the old token is still the current one after a restart";
  EXPECT_EQ(second->session_token.size(), 64u);

  // The guard the web UI setting has: a port this host uses itself is refused, and no token is spent on it.
  const auto saved_port = config::nvhttp.usb_forwarding_port;
  config::nvhttp.usb_forwarding_port = net::map_port(nvhttp::PORT_HTTP);
  failure = remote_usb::start_failure::none;
  const auto before = nvhttp::usb_forwarding_token();
  EXPECT_FALSE(nvhttp::make_usb_tunnel_config(failure).has_value());
  EXPECT_EQ(failure, remote_usb::start_failure::port_refused);
  EXPECT_EQ(nvhttp::usb_forwarding_token(), before);
  config::nvhttp.usb_forwarding_port = saved_port;
}


TEST(UsbControlPipeProtocol, ClientUuidsReachTheBackendInUpperCase) {
  fixture f;
  ASSERT_TRUE(f.start());
  ask_json(f.name, R"({"v":1,"op":"revoke_client","client_uuid":"aB-cd-12"})");
  ask_json(f.name, R"({"v":1,"op":"clear_revoke","client_uuid":"aB-cd-12"})");
  const std::lock_guard lock {f.backend.mutex};
  ASSERT_EQ(f.backend.revoked.size(), 1u);
  EXPECT_EQ(f.backend.revoked[0], "AB-CD-12");
  ASSERT_EQ(f.backend.cleared.size(), 1u);
  EXPECT_EQ(f.backend.cleared[0], "AB-CD-12");
}

TEST(UsbControlPipeProtocol, TheRepliesSayWhetherTheClientIsKnown) {
  fixture f;
  f.backend.revoke_known = false;
  ASSERT_TRUE(f.start());
  EXPECT_EQ(ask_json(f.name, R"({"v":1,"op":"revoke_client","client_uuid":"u-1"})")["known"], false);
  EXPECT_EQ(ask_json(f.name, R"({"v":1,"op":"clear_revoke","client_uuid":"u-1"})")["known"], false);
  f.backend.revoke_known = true;
  EXPECT_EQ(ask_json(f.name, R"({"v":1,"op":"revoke_client","client_uuid":"u-1"})")["known"], true);
}

// ---- the accept loop under a failing wait or connect ----------------------------------------------------------

namespace {

  /** One attempt to open the pipe; 0 when it opened, else the Win32 error. Never waits. */
  DWORD
  probe_error(const std::wstring &name) {
    HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      return GetLastError();
    }
    CloseHandle(h);
    return 0;
  }

  /** Probes for @p span; true when the name was always there (open, or busy, never "not found"). */
  bool
  name_always_present(const std::wstring &name, std::chrono::milliseconds span) {
    const auto end = std::chrono::steady_clock::now() + span;
    while (std::chrono::steady_clock::now() < end) {
      if (probe_error(name) == ERROR_FILE_NOT_FOUND) {
        return false;
      }
      std::this_thread::sleep_for(3ms);
    }
    return true;
  }

}  // namespace

TEST(UsbControlPipeResilience, AFailingWaitKeepsTheNameDoesNotSpinAndStopStillReturns) {
  fixture f;
  auto waits = std::make_shared<std::atomic<int>>(0);
  const auto mark = log_size();
  ASSERT_TRUE(f.start([&](usb_control_pipe_config &c) {
    c.backoff_initial = 25ms;
    c.backoff_max = 25ms;
    c.test_wait_for_connection = [waits](unsigned long, void *const *, unsigned long) -> unsigned long {
      ++(*waits);
      return WAIT_FAILED;
    };
  }));
  EXPECT_TRUE(name_always_present(f.name, 400ms)) << "the pipe name was free at some moment";
  const int iterations = waits->load();
  EXPECT_GE(iterations, 2) << "the loop stopped trying";
  EXPECT_LE(iterations, 40) << "the loop spins: " << iterations << " iterations in 400 ms with a 25 ms pause";
  EXPECT_TRUE(f.pipe->running());
  EXPECT_NE(log_since(mark).find("waiting for a connection failed"), std::string::npos);

  const auto started = std::chrono::steady_clock::now();
  f.pipe->stop();
  EXPECT_LT(std::chrono::steady_clock::now() - started, 2s);
}

TEST(UsbControlPipeResilience, AnInstanceThatFailsToConnectAtOnceIsReplacedWithGrowingPausesNotInAHotLoop) {
  fixture f;
  auto attempts = std::make_shared<std::atomic<int>>(0);
  ASSERT_TRUE(f.start([&](usb_control_pipe_config &c) {
    c.backoff_initial = 25ms;
    c.backoff_max = 400ms;
    c.test_connect_pipe = [attempts](void *, void *) -> int {
      ++(*attempts);
      SetLastError(ERROR_BAD_PIPE);
      return FALSE;
    };
  }));
  EXPECT_TRUE(name_always_present(f.name, 450ms)) << "the pipe name was free at some moment";
  const int count = attempts->load();
  EXPECT_GE(count, 3);
  // Pauses of 25, 50, 100, 200 ms: about five attempts. Resetting the pause after each replacement would make it about eighteen.
  EXPECT_LE(count, 9) << count << " attempts in 450 ms";
  const auto started = std::chrono::steady_clock::now();
  f.pipe->stop();
  EXPECT_LT(std::chrono::steady_clock::now() - started, 2s);
}

// ---- an administrator-run Apollo -----------------------------------------------------------------------------

TEST(UsbControlPipeOwner, WhenOnlyAdministratorsCanBeTheOwnerThePipeIsOwnedByThem) {
  if (!process_is_elevated()) {
    GTEST_SKIP() << "needs an elevated shell: only an elevated administrator can make Administrators the owner";
  }
  fake_backend backend;
  usb_control_pipe_config config;  // production owner rule
  config.name = unique_pipe_name();
  auto owner_seen = std::make_shared<std::string>();
  config.create_pipe = [owner_seen](const wchar_t *name, unsigned long open_mode, unsigned long pipe_mode, unsigned long instances, unsigned long out, unsigned long in, unsigned long timeout, void *attributes) -> void * {
    auto *sa = static_cast<SECURITY_ATTRIBUTES *>(attributes);
    PSID owner = nullptr;
    BOOL defaulted = FALSE;
    // The SYSTEM owner is refused, as it is for an Apollo that does not run as SYSTEM.
    if (sa && sa->lpSecurityDescriptor && GetSecurityDescriptorOwner(sa->lpSecurityDescriptor, &owner, &defaulted) && sid_text(owner) == "S-1-5-18") {
      SetLastError(ERROR_INVALID_OWNER);
      return INVALID_HANDLE_VALUE;
    }
    HANDLE handle = CreateNamedPipeW(name, open_mode, pipe_mode, instances, out, in, timeout, sa);
    if (handle != INVALID_HANDLE_VALUE && owner_seen->empty()) {
      *owner_seen = read_owner(handle);
    }
    return handle;
  };
  usb_control_pipe pipe {backend, config};
  ASSERT_TRUE(pipe.start());
  EXPECT_EQ(*owner_seen, "S-1-5-32-544");
}

#endif  // _WIN32
