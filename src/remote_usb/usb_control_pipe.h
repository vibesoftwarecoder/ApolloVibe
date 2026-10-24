/**
 * @file src/remote_usb/usb_control_pipe.h
 * @brief A Windows named pipe that lets the machine's administrators see and steer USB forwarding.
 * @details Exists only when `usb_forwarding_control` is enabled. No port, no token, no secret file:
 *          the pipe's access control list is the whole authentication of the CLIENT. Only SYSTEM and
 *          BUILTIN\Administrators may open it, and remote clients are refused by the pipe itself.
 *          Apollo creates the pipe only when it can make SYSTEM or Administrators its owner (the
 *          console Apollo runs as SYSTEM). A standard-user Apollo does not create it at all.
 *
 * Wire protocol (version 1), one request per connection:
 *   - The pipe is in byte mode. The client writes ONE UTF-8 JSON object followed by '\n'. The line
 *     including the '\n' must not exceed 4096 bytes. Bytes after the first '\n' are ignored.
 *   - The server answers with ONE JSON object followed by '\n' and then waits for the client to
 *     close its end (so the reply is never cut off), up to the I/O deadline. A connection that
 *     arrives while the connection cap is reached is closed without a reply.
 *   - Request:  {"v":1,"op":"status"}
 *               {"v":1,"op":"set_enabled","enabled":true|false}
 *               {"v":1,"op":"revoke_client","client_uuid":"<uuid>"}
 *               {"v":1,"op":"clear_revoke","client_uuid":"<uuid>"}
 *   - Reply:    {"v":1,"ok":true,...}   or   {"v":1,"ok":false,"error":"<code>"}
 *   - Error codes are fixed words and never contain request text: bad_request (empty, not UTF-8,
 *     not JSON, not an object), too_large, bad_version, unknown_op, bad_field, timeout,
 *     port_refused, start_failed, shutting_down, deny_list_full, internal.
 *
 * CLIENT CONTRACT. The ACL protects the server from the wrong client. It does not protect the client
 * from the wrong server: any local user can create a pipe with this name while Apollo is stopped.
 * Every client, whether it runs as SYSTEM or as an administrator, MUST:
 *   1. pass SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION to CreateFile as part of the OPEN (they
 *      are flags of the open call, not a step after it), so the server can never impersonate the
 *      client; without them a fake server could act as SYSTEM;
 *   2. read the pipe's owner with GetSecurityInfo (the handle needs READ_CONTROL, which
 *      GENERIC_READ includes) and require S-1-5-18 (SYSTEM) or S-1-5-32-544 (Administrators);
 *   3. require GetNamedPipeServerProcessId to equal the process id of the Apollo it expects;
 * and refuse to talk, before sending anything, when any of the three does not hold. The "Apollo it
 * expects" is the process that owns the listening TCP port of the configured Apollo main port
 * (GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER), looked up again for each connection. A process
 * id can be reused after Apollo exits; that window is narrow and the owner check covers it, because a
 * reused id would still have to produce a pipe owned by SYSTEM or Administrators.
 * Every read and write MUST be bounded: open with FILE_FLAG_OVERLAPPED and wait with a timeout, or run
 * the I/O on a thread that can be cancelled. On ERROR_PIPE_BUSY call WaitNamedPipe with a bounded
 * timeout, try again a bounded number of times, then fail. A connection closed with no reply means the
 * server's connection cap was reached (or the server is stopping): treat it as "busy", not as an answer.
 * Out of scope: other administrators and SYSTEM-level processes. An administrator can already stop
 * Apollo and take the pipe name; the owner and process id checks are what separate administrator-level
 * processes from ordinary users, and from each other.
 * Apollo only ever creates the pipe with an owner of SYSTEM or Administrators, and re-checks that on
 * every live instance. The Administrators entry in the access list keeps GENERIC_READ|GENERIC_WRITE
 * because an Apollo run by an elevated administrator needs FILE_CREATE_PIPE_INSTANCE to create its
 * own later instances.
 */
#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace remote_usb {

  struct control_client {
    std::string uuid;
    std::string name;
    bool usb_permission {false};
  };

  struct control_forward {
    std::string client_uuid;
    std::string client_name;
    std::string busid;
    std::int64_t since_unix {0};
  };

  /** Everything `status` may say. There is deliberately no field for a token, a certificate or a key. */
  struct control_status {
    bool enabled {false};
    bool listening {false};
    std::uint16_t port {0};
    bool require_stream {true};
    std::vector<control_forward> forwards;
    std::vector<control_client> clients;
    /** Client uuids refused USB forwarding until Apollo restarts or the entry is cleared. */
    std::vector<std::string> denied;
  };

  enum class control_error : std::uint8_t {
    none,
    port_refused,
    start_failed,
    shutting_down,
    deny_list_full,
    internal,
  };

  struct set_enabled_outcome {
    control_error error {control_error::none};
    /** Whether the change was written to the config file. False means "until Apollo restarts". */
    bool persisted {false};
  };

  struct revoke_outcome {
    control_error error {control_error::none};
    /** Forwards that were running and have been cut. */
    std::size_t forwards_cut {0};
    /** The uuid belongs to a client that is paired right now. An unknown uuid is still denied. */
    bool known {false};
  };

  struct clear_outcome {
    control_error error {control_error::none};
    /** The uuid belongs to a client that is paired right now. */
    bool known {false};
  };

  /** What the pipe asks of Apollo. Must outlive the pipe; calls come from several threads. */
  class usb_control_backend {
  public:
    virtual ~usb_control_backend() = default;

    virtual control_status
    status() = 0;

    virtual set_enabled_outcome
    set_enabled(bool enabled) = 0;

    /**
     * Refuse this client USB forwarding from now on (until Apollo restarts or clear_revoke), then cut its
     * running forwards. Does not unpair the client and does not touch its stored permission.
     */
    virtual revoke_outcome
    revoke_client(const std::string &client_uuid) = 0;

    /** Take the client off the deny list. */
    virtual clear_outcome
    clear_revoke(const std::string &client_uuid) = 0;
  };

  /** Largest request line, including the newline. */
  constexpr std::size_t control_max_request_bytes = 4096;

  /** Parses one request line (without its newline) and runs it. Returns the reply (without newline). Never throws. */
  std::string
  handle_control_request(std::string_view line, usb_control_backend &backend);

  /** True when @p text is well-formed UTF-8 (no overlong forms, surrogates or values above U+10FFFF). */
  bool
  is_valid_utf8(std::string_view text);

  struct usb_control_pipe_config {
    /** Full pipe name, e.g. \\.\pipe\ApolloVibe-usb-control-47989. */
    std::wstring name;
    std::size_t max_request_bytes {control_max_request_bytes};
    /** Deadline for reading a request, and again for writing the reply and waiting for the client to finish. */
    std::chrono::milliseconds io_timeout {std::chrono::seconds(5)};
    /** Connections handled at the same time. */
    std::size_t max_connections {4};
    /** Pause after a failure to create or verify a pipe instance; doubles up to backoff_max. Injectable for tests. */
    std::chrono::milliseconds backoff_initial {std::chrono::milliseconds(50)};
    std::chrono::milliseconds backoff_max {std::chrono::seconds(5)};
    /** TEST ONLY: an extra SDDL SID string (e.g. "S-1-5-21-...") granted the same access, so tests can run
     *  without elevation. Production never sets it. The runtime check expects it. */
    std::wstring test_extra_allowed_sid;
    /** TEST ONLY: an SDDL SID string accepted as owner IN ADDITION to SYSTEM and Administrators, so tests
     *  can run without elevation. Production never sets it. */
    std::wstring test_owner_sid;
    /** TEST ONLY: called with the 1-based number of each verification (the first is the first instance); returning true
     *  makes that verification fail. Windows gives every later instance the access list of the first, so a bad
     *  instance cannot otherwise be provoked. */
    std::function<bool(unsigned)> test_fail_verification;
        /** TEST ONLY: replaces the wait for a connection (count, handles, milliseconds) in the accept loop. */
    std::function<unsigned long(unsigned long, void *const *, unsigned long)> test_wait_for_connection;
    /** TEST ONLY: replaces ConnectNamedPipe(pipe, overlapped); returns its BOOL and sets the last error like it. */
    std::function<int(void *, void *)> test_connect_pipe;
        /** TEST ONLY: replaces CreateNamedPipeW (same arguments; HANDLE and SECURITY_ATTRIBUTES* as void*). */
    std::function<void *(const wchar_t *, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, void *)> create_pipe;
  };

  /** `\\.\pipe\ApolloVibe-usb-control-<main port>` */
  std::wstring
  usb_control_pipe_name(std::uint16_t main_port);

  class usb_control_pipe final {
  public:
    usb_control_pipe(usb_control_backend &backend, usb_control_pipe_config config);
    ~usb_control_pipe();

    usb_control_pipe(const usb_control_pipe &) = delete;
    usb_control_pipe &
    operator=(const usb_control_pipe &) = delete;

    /**
     * Creates the pipe and starts serving. Fails closed (one log line, returns false) when the name is
     * taken, when Apollo cannot make SYSTEM or Administrators the owner, when the descriptor cannot be
     * built, or when the live pipe does not carry the intended owner and DACL.
     */
    bool
    start();

    /** Stops accepting, cancels every connection and joins the threads. Any thread, any number of times. */
    void
    stop() noexcept;

    bool
    running() const noexcept {
      return running_.load();
    }

  private:
    struct worker {
      std::thread thread;
      std::atomic_bool done {false};
    };

    void *
    create_instance(bool first);
    bool
    verify_instance(void *pipe);
    /** A new instance that passed the check, or null (the failure is already logged, rate limited). */
    void *
    acquire_instance();
    void
    accept_loop(void *first_instance);
    void
    serve(void *pipe);
    void
    reap_workers(bool all);

    usb_control_backend &backend_;
    usb_control_pipe_config config_;
    void *security_descriptor_ {nullptr};  // PSECURITY_DESCRIPTOR, allocated by the SDDL converter
    void *stop_event_ {nullptr};
    std::mutex mutex_;  // guards start/stop and the thread bookkeeping
    std::mutex stop_mutex_;  // serialises the joining half of stop()
    std::atomic_bool running_ {false};
    std::atomic_bool stopping_ {false};
    std::atomic<std::size_t> active_ {0};
    std::thread accept_thread_;
    std::list<std::unique_ptr<worker>> workers_;
    std::chrono::steady_clock::time_point last_failure_log_ {};
    unsigned verify_count_ {0};
  };

  /**
   * @brief The one place that decides whether the control pipe exists at all.
   * @param enabled `usb_forwarding_control`. When false nothing is created: no pipe, no thread, no log line.
   * @return The running pipe, or null when it is off or could not be started (the reason is logged).
   */
  std::unique_ptr<usb_control_pipe>
  start_usb_control_pipe_if_enabled(bool enabled, usb_control_backend &backend, usb_control_pipe_config config);

}  // namespace remote_usb
