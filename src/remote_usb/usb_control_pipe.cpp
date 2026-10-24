/**
 * @file src/remote_usb/usb_control_pipe.cpp
 */
#include "src/remote_usb/usb_control_pipe.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// clang-format off
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
// clang-format on

#include "src/logging.h"

namespace remote_usb {

  using namespace std::literals;

  namespace {
    constexpr std::size_t max_listed_entries = 512;

    // ---- the protocol -------------------------------------------------------------------------------------

    std::string
    error_reply(const char *code) {
      return nlohmann::json {{"v", 1}, {"ok", false}, {"error", code}}.dump();
    }

    std::string
    dump_safe(const nlohmann::json &value) {
      // Names come from paired clients; an invalid byte must not turn into an exception.
      return value.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    }

    const char *
    error_text(control_error error) {
      switch (error) {
        case control_error::port_refused:
          return "port_refused";
        case control_error::start_failed:
          return "start_failed";
        case control_error::shutting_down:
          return "shutting_down";
        case control_error::deny_list_full:
          return "deny_list_full";
        case control_error::none:
          return "";
        case control_error::internal:
        default:
          return "internal";
      }
    }

    void
    log_request(const char *op, const char *outcome) {
      BOOST_LOG(info) << "USB control request: op="sv << op << " outcome="sv << outcome;
    }

    std::string
    fail(const char *op, const char *code) {
      log_request(op, code);
      return error_reply(code);
    }

    nlohmann::json
    status_json(const control_status &status) {
      nlohmann::json forwards = nlohmann::json::array();
      for (const auto &forward : status.forwards) {
        if (forwards.size() >= max_listed_entries) {
          break;
        }
        forwards.push_back({
          {"client_uuid", forward.client_uuid},
          {"client_name", forward.client_name},
          {"busid", forward.busid},
          {"since_unix", forward.since_unix},
        });
      }
      nlohmann::json clients = nlohmann::json::array();
      for (const auto &client : status.clients) {
        if (clients.size() >= max_listed_entries) {
          break;
        }
        clients.push_back({
          {"uuid", client.uuid},
          {"name", client.name},
          {"usb_permission", client.usb_permission},
        });
      }
      nlohmann::json denied = nlohmann::json::array();
      for (const auto &uuid : status.denied) {
        if (denied.size() >= max_listed_entries) {
          break;
        }
        denied.push_back(uuid);
      }
      return {
        {"enabled", status.enabled},
        {"listening", status.listening},
        {"port", status.port},
        {"require_stream", status.require_stream},
        {"forwards", std::move(forwards)},
        {"clients", std::move(clients)},
        {"denied", std::move(denied)},
      };
    }

    /** The form paired clients are stored in. */
    std::string
    canonical_uuid(std::string text) {
      for (auto &c : text) {
        if (c >= 'a' && c <= 'z') {
          c = static_cast<char>(c - 'a' + 'A');
        }
      }
      return text;
    }

    bool
    valid_uuid_text(const std::string &text) {
      if (text.empty() || text.size() > 64) {
        return false;
      }
      return std::all_of(text.begin(), text.end(), [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '-';
      });
    }

    // ---- Win32 helpers ------------------------------------------------------------------------------------

    struct local_free {
      void
      operator()(void *p) const {
        if (p) {
          LocalFree(p);
        }
      }
    };
    using local_ptr = std::unique_ptr<void, local_free>;

    std::wstring
    descriptor_sddl(const std::wstring &owner, const std::wstring &extra_sid) {
      // The owner is always named: an unnamed owner would be whoever created the pipe, and an owner can
      // rewrite the access list.
      std::wstring text = L"O:" + owner;
      // Protected DACL, two allow entries and nothing else: no Everyone, Users or Authenticated Users.
      text += L"D:P(A;;GRGW;;;SY)(A;;GRGW;;;BA)";
      if (!extra_sid.empty()) {
        text += L"(A;;GRGW;;;" + extra_sid + L")";
      }
      return text;
    }

    /** The exact set of SIDs the DACL must list, as SDDL SID strings. */
    std::vector<std::wstring>
    intended_sids(const std::wstring &extra_sid) {
      std::vector<std::wstring> sids {L"SY", L"BA"};
      if (!extra_sid.empty()) {
        sids.push_back(extra_sid);
      }
      return sids;
    }

    /** Whether the live object is owned by SYSTEM or Administrators (or the test owner) and carries exactly the intended DACL. Any doubt is a no. */
    bool
    security_is_intended(HANDLE pipe, const std::wstring &extra_sid, const std::wstring &test_owner) {
      PSECURITY_DESCRIPTOR sd = nullptr;
      PACL dacl = nullptr;
      PSID owner = nullptr;
      if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS) {
        return false;
      }
      local_ptr guard {sd};
      if (!owner) {
        return false;
      }
      {
        std::vector<std::wstring> owners {L"SY", L"BA"};
        if (!test_owner.empty()) {
          owners.push_back(test_owner);
        }
        bool owner_ok = false;
        for (const auto &name : owners) {
          PSID allowed = nullptr;
          if (ConvertStringSidToSidW(name.c_str(), &allowed)) {
            owner_ok = owner_ok || EqualSid(owner, allowed);
            LocalFree(allowed);
          }
        }
        if (!owner_ok) {
          return false;
        }
      }
      if (!dacl) {
        return false;  // a null DACL grants everyone everything
      }

      const auto expected_names = intended_sids(extra_sid);
      std::vector<local_ptr> expected;
      for (const auto &name : expected_names) {
        PSID sid = nullptr;
        if (!ConvertStringSidToSidW(name.c_str(), &sid)) {
          return false;
        }
        expected.emplace_back(sid);
      }

      ACL_SIZE_INFORMATION info {};
      if (!GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation) || info.AceCount != expected.size()) {
        return false;
      }

      GENERIC_MAPPING mapping {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
      DWORD want = GENERIC_READ | GENERIC_WRITE;
      MapGenericMask(&want, &mapping);

      std::vector<bool> seen(expected.size(), false);
      for (DWORD i = 0; i < info.AceCount; ++i) {
        void *raw = nullptr;
        if (!GetAce(dacl, i, &raw) || !raw) {
          return false;
        }
        const auto *header = static_cast<const ACE_HEADER *>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0) {
          return false;
        }
        const auto *ace = static_cast<const ACCESS_ALLOWED_ACE *>(raw);
        DWORD mask = ace->Mask;
        MapGenericMask(&mask, &mapping);
        if (mask != want) {
          return false;
        }
        bool matched = false;
        for (std::size_t j = 0; j < expected.size(); ++j) {
          if (!seen[j] && EqualSid(const_cast<PSID>(static_cast<const void *>(&ace->SidStart)), expected[j].get())) {
            seen[j] = true;
            matched = true;
            break;
          }
        }
        if (!matched) {
          return false;
        }
      }
      return true;
    }

    enum class io_status { done, timeout, stopped, failed };

    /**
     * Finishes one overlapped call that was just started with @p started.
     * Waits for it, the stop event or the deadline; on the last two it cancels the call and waits for the
     * cancellation, so the OVERLAPPED and the buffer are free to go when this returns.
     */
    io_status
    finish_io(HANDLE pipe, OVERLAPPED &ov, BOOL started, HANDLE stop_event, std::chrono::steady_clock::time_point deadline, DWORD &bytes, DWORD &error) {
      bytes = 0;
      error = 0;
      if (started) {
        return GetOverlappedResult(pipe, &ov, &bytes, FALSE) ? io_status::done : (error = GetLastError(), io_status::failed);
      }
      error = GetLastError();
      if (error != ERROR_IO_PENDING) {
        return io_status::failed;
      }

      const auto now = std::chrono::steady_clock::now();
      const auto remaining = deadline > now ? std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now) : 0ms;
      HANDLE handles[2] = {ov.hEvent, stop_event};
      const DWORD waited = WaitForMultipleObjects(2, handles, FALSE, static_cast<DWORD>(remaining.count()));
      if (waited == WAIT_OBJECT_0) {
        return GetOverlappedResult(pipe, &ov, &bytes, FALSE) ? io_status::done : (error = GetLastError(), io_status::failed);
      }

      CancelIoEx(pipe, &ov);
      if (GetOverlappedResult(pipe, &ov, &bytes, TRUE)) {
        return io_status::done;  // it finished before the cancel took hold; the data is real
      }
      error = GetLastError();
      return waited == WAIT_OBJECT_0 + 1 ? io_status::stopped : io_status::timeout;
    }

    struct event_handle {
      HANDLE handle {CreateEventW(nullptr, TRUE, FALSE, nullptr)};
      ~event_handle() {
        if (handle) {
          CloseHandle(handle);
        }
      }
      event_handle() = default;
      event_handle(const event_handle &) = delete;
      event_handle &
      operator=(const event_handle &) = delete;
    };

    enum class read_outcome { line, too_large, timeout, stopped, gone };

    read_outcome
    read_request(HANDLE pipe, HANDLE stop_event, std::size_t limit, std::chrono::steady_clock::time_point deadline, std::string &line) {
      event_handle event;
      if (!event.handle) {
        return read_outcome::gone;
      }
      std::string data;
      std::vector<char> chunk(limit + 1);
      while (true) {
        const std::size_t room = limit + 1 - data.size();
        OVERLAPPED ov {};
        ov.hEvent = event.handle;
        ResetEvent(event.handle);
        DWORD got = 0;
        DWORD error = 0;
        const BOOL started = ReadFile(pipe, chunk.data(), static_cast<DWORD>(room), nullptr, &ov);
        switch (finish_io(pipe, ov, started, stop_event, deadline, got, error)) {
          case io_status::done:
            break;
          case io_status::timeout:
            return read_outcome::timeout;
          case io_status::stopped:
            return read_outcome::stopped;
          case io_status::failed:
            return read_outcome::gone;
        }
        data.append(chunk.data(), got);
        const auto newline = data.find('\n');
        if (newline != std::string::npos) {
          if (newline + 1 > limit) {
            return read_outcome::too_large;
          }
          line = data.substr(0, newline);
          if (!line.empty() && line.back() == '\r') {
            line.pop_back();
          }
          return read_outcome::line;
        }
        if (data.size() > limit) {
          return read_outcome::too_large;
        }
        if (got == 0) {
          return read_outcome::gone;
        }
      }
    }

    /** Writes everything or gives up at the deadline. */
    bool
    write_all(HANDLE pipe, HANDLE stop_event, std::chrono::steady_clock::time_point deadline, const std::string &data) {
      event_handle event;
      if (!event.handle) {
        return false;
      }
      std::size_t sent = 0;
      while (sent < data.size()) {
        OVERLAPPED ov {};
        ov.hEvent = event.handle;
        ResetEvent(event.handle);
        DWORD wrote = 0;
        DWORD error = 0;
        const BOOL started = WriteFile(pipe, data.data() + sent, static_cast<DWORD>(data.size() - sent), nullptr, &ov);
        if (finish_io(pipe, ov, started, stop_event, deadline, wrote, error) != io_status::done || wrote == 0) {
          return false;
        }
        sent += wrote;
      }
      return true;
    }

    /** Reads and drops whatever the client sends until it closes its end, the deadline passes or we stop. */
    void
    wait_for_client_to_finish(HANDLE pipe, HANDLE stop_event, std::chrono::steady_clock::time_point deadline) {
      event_handle event;
      if (!event.handle) {
        return;
      }
      char scratch[64];
      while (true) {
        OVERLAPPED ov {};
        ov.hEvent = event.handle;
        ResetEvent(event.handle);
        DWORD got = 0;
        DWORD error = 0;
        const BOOL started = ReadFile(pipe, scratch, sizeof(scratch), nullptr, &ov);
        if (finish_io(pipe, ov, started, stop_event, deadline, got, error) != io_status::done || got == 0) {
          return;
        }
      }
    }
  }  // namespace

  // ---- UTF-8 ----------------------------------------------------------------------------------------------

  bool
  is_valid_utf8(std::string_view text) {
    std::size_t i = 0;
    const auto n = text.size();
    while (i < n) {
      const auto c = static_cast<unsigned char>(text[i]);
      std::size_t extra;
      std::uint32_t code;
      if (c < 0x80) {
        ++i;
        continue;
      }
      else if (c >= 0xC2 && c <= 0xDF) {
        extra = 1;
        code = c & 0x1F;
      }
      else if (c >= 0xE0 && c <= 0xEF) {
        extra = 2;
        code = c & 0x0F;
      }
      else if (c >= 0xF0 && c <= 0xF4) {
        extra = 3;
        code = c & 0x07;
      }
      else {
        return false;
      }
      if (i + extra >= n) {
        return false;
      }
      for (std::size_t k = 1; k <= extra; ++k) {
        const auto cc = static_cast<unsigned char>(text[i + k]);
        if ((cc & 0xC0) != 0x80) {
          return false;
        }
        code = (code << 6) | (cc & 0x3F);
      }
      if ((extra == 2 && code < 0x800) || (extra == 3 && code < 0x10000) || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF)) {
        return false;
      }
      i += extra + 1;
    }
    return true;
  }

  // ---- request handling -----------------------------------------------------------------------------------

  std::string
  handle_control_request(std::string_view line, usb_control_backend &backend) {
    try {
      if (line.empty() || !is_valid_utf8(line)) {
        return fail("unknown", "bad_request");
      }
      if (line.size() > control_max_request_bytes) {
        return fail("unknown", "too_large");
      }
      const auto request = nlohmann::json::parse(line.begin(), line.end(), nullptr, false);
      if (request.is_discarded() || !request.is_object()) {
        return fail("unknown", "bad_request");
      }

      const auto version = request.find("v");
      if (version == request.end() || !version->is_number_integer()) {
        return fail("unknown", "bad_field");
      }
      if (version->get<std::int64_t>() != 1) {
        return fail("unknown", "bad_version");
      }
      const auto op_field = request.find("op");
      if (op_field == request.end() || !op_field->is_string()) {
        return fail("unknown", "bad_field");
      }
      const auto op = op_field->get<std::string>();

      if (op == "status") {
        auto body = status_json(backend.status());
        body["v"] = 1;
        body["ok"] = true;
        log_request("status", "ok");
        return dump_safe(body);
      }

      if (op == "set_enabled") {
        const auto enabled = request.find("enabled");
        if (enabled == request.end() || !enabled->is_boolean()) {
          return fail("set_enabled", "bad_field");
        }
        const auto want = enabled->get<bool>();
        const auto outcome = backend.set_enabled(want);
        if (outcome.error != control_error::none) {
          return fail("set_enabled", error_text(outcome.error));
        }
        auto body = status_json(backend.status());
        // The reply carries the state only; the lists stay in `status`.
        nlohmann::json reply {
          {"v", 1},
          {"ok", true},
          {"enabled", body["enabled"]},
          {"listening", body["listening"]},
          {"port", body["port"]},
          {"persisted", outcome.persisted},
        };
        log_request("set_enabled", want ? "ok enabled" : "ok disabled");
        return dump_safe(reply);
      }

      if (op == "revoke_client") {
        const auto uuid = request.find("client_uuid");
        if (uuid == request.end() || !uuid->is_string() || !valid_uuid_text(uuid->get<std::string>())) {
          return fail("revoke_client", "bad_field");
        }
        const auto outcome = backend.revoke_client(canonical_uuid(uuid->get<std::string>()));
        if (outcome.error != control_error::none) {
          return fail("revoke_client", error_text(outcome.error));
        }
        log_request("revoke_client", "ok");
        return dump_safe(nlohmann::json {{"v", 1}, {"ok", true}, {"forwards_cut", outcome.forwards_cut}, {"denied", true}, {"known", outcome.known}});
      }

      if (op == "clear_revoke") {
        const auto uuid = request.find("client_uuid");
        if (uuid == request.end() || !uuid->is_string() || !valid_uuid_text(uuid->get<std::string>())) {
          return fail("clear_revoke", "bad_field");
        }
        const auto outcome = backend.clear_revoke(canonical_uuid(uuid->get<std::string>()));
        if (outcome.error != control_error::none) {
          return fail("clear_revoke", error_text(outcome.error));
        }
        log_request("clear_revoke", "ok");
        return dump_safe(nlohmann::json {{"v", 1}, {"ok", true}, {"denied", false}, {"known", outcome.known}});
      }

      return fail("unknown", "unknown_op");
    }
    catch (...) {
      return fail("unknown", "internal");
    }
  }

  std::wstring
  usb_control_pipe_name(std::uint16_t main_port) {
    return L"\\\\.\\pipe\\ApolloVibe-usb-control-" + std::to_wstring(main_port);
  }

  // ---- the pipe -------------------------------------------------------------------------------------------

  usb_control_pipe::usb_control_pipe(usb_control_backend &backend, usb_control_pipe_config config):
      backend_(backend),
      config_(std::move(config)) {}

  usb_control_pipe::~usb_control_pipe() {
    stop();
  }

  void *
  usb_control_pipe::create_instance(bool first) {
    const DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
    const DWORD pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    SECURITY_ATTRIBUTES attributes {sizeof(attributes), security_descriptor_, FALSE};
    const auto instances = static_cast<DWORD>(config_.max_connections + 2);  // the busy ones, one just connected, one waiting
    const auto buffer = static_cast<DWORD>(config_.max_request_bytes);
    void *handle;
    if (config_.create_pipe) {
      handle = config_.create_pipe(config_.name.c_str(), open_mode, pipe_mode, instances, buffer, buffer, 0, &attributes);
    }
    else {
      handle = CreateNamedPipeW(config_.name.c_str(), open_mode, pipe_mode, instances, buffer, buffer, 0, &attributes);
    }
    return handle == INVALID_HANDLE_VALUE ? nullptr : handle;
  }

  bool
  usb_control_pipe::verify_instance(void *pipe) {
    if (config_.test_fail_verification && config_.test_fail_verification(++verify_count_)) {
      return false;
    }
    return security_is_intended(static_cast<HANDLE>(pipe), config_.test_extra_allowed_sid, config_.test_owner_sid);
  }

  bool
  usb_control_pipe::start() {
    const std::lock_guard lock {mutex_};
    if (running_.load() || stopping_.load() || stop_event_) {
      return false;  // single use
    }

    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop_event_) {
      BOOST_LOG(warning) << "USB control pipe stays off: cannot create its stop event"sv;
      return false;
    }

    // Owner SYSTEM if this process may assign it, else Administrators. There is no third choice: a pipe
    // owned by whoever happened to create it could have its access list rewritten by that user.
    void *first = nullptr;
    DWORD last_error = ERROR_SUCCESS;
    std::vector<std::wstring> owners {L"SY", L"BA"};
    if (!config_.test_owner_sid.empty()) {
      owners = {config_.test_owner_sid};
    }
    for (const auto &owner : owners) {
      PSECURITY_DESCRIPTOR sd = nullptr;
      if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor_sddl(owner, config_.test_extra_allowed_sid).c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        BOOST_LOG(warning) << "USB control pipe stays off: cannot build its access list"sv;
        break;
      }
      security_descriptor_ = sd;
      first = create_instance(true);
      if (first) {
        break;
      }
      last_error = GetLastError();
      LocalFree(security_descriptor_);
      security_descriptor_ = nullptr;
      if (last_error != ERROR_INVALID_OWNER) {
        break;
      }
    }

    if (!first) {
      if (last_error == ERROR_INVALID_OWNER) {
        BOOST_LOG(warning) << "USB control pipe stays off: Apollo cannot make SYSTEM or Administrators the owner of the pipe (is it running as a standard user?)"sv;
      }
      else if (last_error == ERROR_ACCESS_DENIED || last_error == ERROR_PIPE_BUSY) {
        BOOST_LOG(warning) << "USB control pipe stays off: the pipe name is already in use"sv;
      }
      else {
        BOOST_LOG(warning) << "USB control pipe stays off: it could not be created (error "sv << last_error << ')';
      }
    }
    else if (!verify_instance(first)) {
      BOOST_LOG(error) << "USB control pipe stays off: the live pipe does not carry the intended owner and access list"sv;
      CloseHandle(static_cast<HANDLE>(first));
      first = nullptr;
    }

    if (!first) {
      if (security_descriptor_) {
        LocalFree(security_descriptor_);
        security_descriptor_ = nullptr;
      }
      CloseHandle(static_cast<HANDLE>(stop_event_));
      stop_event_ = nullptr;
      return false;
    }

    running_ = true;
    accept_thread_ = std::thread([this, first] { accept_loop(first); });
    BOOST_LOG(info) << "USB control pipe listening (administrators only)"sv;
    return true;
  }

  void
  usb_control_pipe::reap_workers(bool all) {
    std::list<std::unique_ptr<worker>> finished;
    {
      const std::lock_guard lock {mutex_};
      for (auto it = workers_.begin(); it != workers_.end();) {
        if (all || (*it)->done.load()) {
          finished.push_back(std::move(*it));
          it = workers_.erase(it);
        }
        else {
          ++it;
        }
      }
    }
    for (auto &w : finished) {
      if (w->thread.joinable()) {
        w->thread.join();
      }
    }
  }

  void *
  usb_control_pipe::acquire_instance() {
    HANDLE handle = static_cast<HANDLE>(create_instance(false));
    const auto now = std::chrono::steady_clock::now();
    const bool may_log = last_failure_log_ == std::chrono::steady_clock::time_point {} || now - last_failure_log_ >= std::chrono::seconds(30);
    if (!handle) {
      if (may_log) {
        last_failure_log_ = now;
        BOOST_LOG(warning) << "USB control pipe could not create a new instance (error "sv << GetLastError() << "); retrying"sv;
      }
      return nullptr;
    }
    if (!verify_instance(handle)) {
      if (may_log) {
        last_failure_log_ = now;
        BOOST_LOG(error) << "USB control pipe refused a new instance: it does not carry the intended owner and access list; retrying"sv;
      }
      CloseHandle(handle);
      return nullptr;
    }
    return handle;
  }

  void
  usb_control_pipe::accept_loop(void *first_instance) {
    auto *stop = static_cast<HANDLE>(stop_event_);
    HANDLE pending = static_cast<HANDLE>(first_instance);
    auto backoff = config_.backoff_initial;

    const auto note_failure = [&](const char *what) {
      const auto now = std::chrono::steady_clock::now();
      if (last_failure_log_ == std::chrono::steady_clock::time_point {} || now - last_failure_log_ >= std::chrono::seconds(30)) {
        last_failure_log_ = now;
        BOOST_LOG(warning) << "USB control pipe: "sv << what << "; retrying"sv;
      }
    };

    // Waits out a failure, doubling the pause up to the limit. False when the pipe is being stopped.
    const auto pause = [&]() {
      const bool stopped = WaitForSingleObject(stop, static_cast<DWORD>(backoff.count())) == WAIT_OBJECT_0;
      backoff = (std::min)(backoff * 2, config_.backoff_max);
      return !stopped && !stopping_.load();
    };

    // The loop never leaves because something failed to be created or checked: it keeps the instance it
    // has (so the name stays taken) and tries again. Only stop() ends it.
    while (!stopping_.load()) {
      reap_workers(false);

      event_handle event;
      if (!event.handle) {
        if (!pause()) {
          break;
        }
        continue;
      }

      OVERLAPPED ov {};
      ov.hEvent = event.handle;
      DWORD ignored = 0;
      DWORD err_code = 0;
      bool connected = false;
      const BOOL started = config_.test_connect_pipe ? config_.test_connect_pipe(pending, &ov) : ConnectNamedPipe(pending, &ov);
      if (started) {
        connected = true;
      }
      else {
        err_code = GetLastError();
        if (err_code == ERROR_PIPE_CONNECTED) {
          connected = true;
        }
        else if (err_code == ERROR_IO_PENDING) {
          HANDLE handles[2] = {event.handle, stop};
          const DWORD waited = config_.test_wait_for_connection ? config_.test_wait_for_connection(2, handles, INFINITE) : WaitForMultipleObjects(2, handles, FALSE, INFINITE);
          if (waited == WAIT_OBJECT_0) {
            connected = GetOverlappedResult(pending, &ov, &ignored, FALSE) != FALSE;
            if (!connected) {
              err_code = GetLastError();
            }
          }
          else {
            CancelIoEx(pending, &ov);
            GetOverlappedResult(pending, &ov, &ignored, TRUE);
            if (waited == WAIT_OBJECT_0 + 1) {
              break;  // the stop event: the only reason to leave
            }
            // The wait itself failed. The instance is untouched and still holds the name: say so, pause, listen again.
            note_failure("waiting for a connection failed");
            if (!pause()) {
              break;
            }
            continue;
          }
        }
      }

      if (!connected) {
        if (stopping_.load()) {
          break;
        }
        if (err_code == ERROR_NO_DATA) {
          // A client came and went before we looked. The instance is fine: reuse it, the name stays held.
          if (!DisconnectNamedPipe(pending)) {
            note_failure("could not reset an instance");
            if (!pause()) {
              break;
            }
          }
          continue;
        }
        // The instance is unusable. Its replacement exists (and passed the check) before it is closed.
        // The pause applies either way and the backoff is NOT reset here: only a connection that was accepted
        // resets it, so an instance that keeps failing at once is not replaced in a hot loop.
        if (HANDLE replacement = static_cast<HANDLE>(acquire_instance())) {
          CloseHandle(pending);
          pending = replacement;
        }
        note_failure("an instance could not accept a connection");
        if (!pause()) {
          break;
        }
        continue;
      }

      // Another instance must exist before this one is handed away, so the name is never free.
      const bool at_cap = active_.load() >= config_.max_connections;
      HANDLE next = static_cast<HANDLE>(acquire_instance());
      if (!next) {
        // Cannot make a new one now. Keep this instance as the waiting one (dropping its client) so the
        // name stays taken, and try again after a pause.
        DisconnectNamedPipe(pending);
        if (!pause()) {
          break;
        }
        continue;
      }
      backoff = config_.backoff_initial;
      HANDLE client = pending;
      pending = next;

      if (at_cap || stopping_.load()) {
        // Over the cap: closed without a reply. Closed only after the next instance exists.
        CloseHandle(client);
        continue;
      }

      auto entry = std::make_unique<worker>();
      auto *raw = entry.get();
      active_.fetch_add(1);
      try {
        const std::lock_guard lock {mutex_};
        entry->thread = std::thread([this, raw, client] {
          try {
            serve(client);
          }
          catch (...) {
          }
          active_.fetch_sub(1);
          raw->done = true;
        });
        workers_.push_back(std::move(entry));
      }
      catch (...) {
        active_.fetch_sub(1);
        CloseHandle(client);
      }
    }

    if (pending) {
      CloseHandle(pending);
    }
    running_ = false;
  }

  void
  usb_control_pipe::serve(void *pipe_handle) {
    auto *pipe = static_cast<HANDLE>(pipe_handle);
    auto *stop = static_cast<HANDLE>(stop_event_);
    const auto now = std::chrono::steady_clock::now();

    std::string line;
    std::string reply;
    switch (read_request(pipe, stop, config_.max_request_bytes, now + config_.io_timeout, line)) {
      case read_outcome::line:
        reply = handle_control_request(line, backend_);
        break;
      case read_outcome::too_large:
        reply = fail("unknown", "too_large");
        break;
      case read_outcome::timeout:
        reply = fail("unknown", "timeout");
        break;
      case read_outcome::stopped:
      case read_outcome::gone:
        break;
    }

    if (!reply.empty()) {
      reply.push_back('\n');
      const auto write_deadline = std::chrono::steady_clock::now() + config_.io_timeout;
      if (write_all(pipe, stop, write_deadline, reply)) {
        // Closing now could cut off a reply the client has not read yet.
        wait_for_client_to_finish(pipe, stop, write_deadline);
      }
    }
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
  }

  void
  usb_control_pipe::stop() noexcept {
    try {
      stopping_ = true;
      {
        const std::lock_guard lock {mutex_};
        if (stop_event_) {
          SetEvent(static_cast<HANDLE>(stop_event_));
        }
        // Called from one of our own threads: signal only. The owner's destructor joins.
        const auto self = std::this_thread::get_id();
        if (accept_thread_.get_id() == self) {
          return;
        }
        for (const auto &w : workers_) {
          if (w->thread.get_id() == self) {
            return;
          }
        }
      }

      // One caller at a time past this point, so nobody frees the stop event while another still joins.
      const std::lock_guard stop_lock {stop_mutex_};

      std::thread accept;
      {
        const std::lock_guard lock {mutex_};
        accept = std::move(accept_thread_);
      }
      if (accept.joinable()) {
        accept.join();
      }
      reap_workers(true);

      const std::lock_guard lock {mutex_};
      if (stop_event_ && !accept_thread_.joinable() && workers_.empty()) {
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
        if (security_descriptor_) {
          LocalFree(security_descriptor_);
          security_descriptor_ = nullptr;
        }
      }
      running_ = false;
    }
    catch (...) {
    }
  }

  std::unique_ptr<usb_control_pipe>
  start_usb_control_pipe_if_enabled(bool enabled, usb_control_backend &backend, usb_control_pipe_config config) {
    if (!enabled) {
      return nullptr;
    }
    auto pipe = std::make_unique<usb_control_pipe>(backend, std::move(config));
    if (!pipe->start()) {
      return nullptr;
    }
    return pipe;
  }

}  // namespace remote_usb
