/**
 * @file src/remote_usb/reverse_tunnel_service.cpp
 *
 * Derived from AlkaidLab/foundation-sunshine (GPL-3.0).
 */

#include "src/remote_usb/reverse_tunnel_service.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <nlohmann/json.hpp>

#include <openssl/crypto.h>
#include <openssl/x509.h>

#ifdef _WIN32
  // clang-format off
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h>
  // clang-format on
#endif

#include "src/logging.h"

#include "src/remote_usb/remote_usb_host_controller.h"
#include "src/remote_usb/usbip_endpoint.h"

namespace remote_usb {

  namespace asio = boost::asio;
  using tcp = asio::ip::tcp;
  namespace ssl = asio::ssl;

  std::optional<std::uint32_t>
  tcp_loopback_peer_pid(std::uint16_t peer_port, std::uint16_t listener_port) {
#ifdef _WIN32
    // The connecting socket's own row: local = 127.0.0.1:peer_port, remote = 127.0.0.1:listener_port.
    // The accepted socket's row is the mirror image and belongs to this process, so matching on
    // both ports and both addresses picks out the connector only.
    std::vector<unsigned char> buffer(16 * 1024);
    for (int attempt = 0; attempt < 5; ++attempt) {
      ULONG size = static_cast<ULONG>(buffer.size());
      const ULONG status = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
      if (status == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(static_cast<std::size_t>(size) + 4096);
        continue;
      }
      if (status != NO_ERROR) {
        return std::nullopt;
      }
      const auto *table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID *>(buffer.data());
      const DWORD loopback = htonl(INADDR_LOOPBACK);
      for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &row = table->table[i];
        if (row.dwLocalAddr == loopback && row.dwRemoteAddr == loopback &&
            ntohs(static_cast<u_short>(row.dwLocalPort)) == peer_port &&
            ntohs(static_cast<u_short>(row.dwRemotePort)) == listener_port) {
          return static_cast<std::uint32_t>(row.dwOwningPid);
        }
      }
      return std::nullopt;
    }
    return std::nullopt;
#else
    (void) peer_port;
    (void) listener_port;
    return std::nullopt;
#endif
  }

  namespace {

    /** Upper bound for the JSON handshake line, mirroring the client. */
    constexpr std::size_t kMaxHandshakeBytes = 4 * 1024;

    /** Constant-time comparison for the shared session token. */
    bool
    tokens_equal(const std::string &a, const std::string &b) {
      return a.size() == b.size() &&
             CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
    }

    using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;

    x509_ptr
    peer_certificate(SSL *ssl) {
#if OPENSSL_VERSION_MAJOR >= 3
      return x509_ptr { SSL_get1_peer_certificate(ssl), &X509_free };
#else
      return x509_ptr { SSL_get_peer_certificate(ssl), &X509_free };
#endif
    }

    /** One accepted client connection and its attached usbip-win2 binding. */
    class tunnel_session: public std::enable_shared_from_this<tunnel_session> {
    public:
      tunnel_session(tcp::socket socket,
                     ssl::context &ssl_context,
                     usbip_host_controller &controller,
                     std::string remote_address):
          stream_(std::move(socket), ssl_context),
          controller_(controller),
          remote_address_(std::move(remote_address)),
          startup_timer_(stream_.get_executor()) {}

      void
      start(reverse_tunnel_config config) {
        config_ = std::move(config);
        if (!config_.attach_peer_pid_lookup) {
          config_.attach_peer_pid_lookup = tcp_loopback_peer_pid;
        }
        // TLS has its own, shorter deadline; the longer one starts once TLS is done.
        arm_deadline(config_.tls_timeout);

        auto self = shared_from_this();
        stream_.async_handshake(ssl::stream_base::server,
          [self](boost::system::error_code error) {
            if (error) {
              // Scanners and half-open probes land here all day; not worth a line at info.
              BOOST_LOG(debug) << "Remote USB tunnel TLS rejected: " << error.message();
              self->finish();
              return;
            }
            self->peer_cert_ = peer_certificate(self->stream_.native_handle());
            self->arm_deadline(self->config_.startup_timeout);
            self->read_handshake();
          });
      }

      /** Close both sockets and release the device slot; any thread, idempotent. */
      void
      abort() {
        // Socket operations are serialized on the service thread.
        asio::post(stream_.get_executor(), [self = shared_from_this()] {
          self->finish();
        });
      }

      /** Whether the session has terminated (slot may be reclaimed). */
      bool
      done() const noexcept {
        return finished_.load();
      }

      /** Passed the token and the authorizer. */
      bool
      authenticated() const noexcept {
        return authenticated_.load();
      }

      const std::string &
      remote_address() const noexcept {
        return remote_address_;
      }

      /** Service thread only. */
      const std::string &
      client_id() const noexcept {
        return client_id_;
      }

      /** Service thread only. */
      forward_info
      describe() const {
        return { client_id_, busid_, since_unix_ };
      }

      /** Ask the authorizer again; cut the forward when the answer is no longer "allowed". Service thread only. */
      void
      recheck() {
        if (finished_.load() || !authenticated_.load() || !peer_cert_) {
          return;
        }
        const auto answer = config_.authorize_client(peer_cert_.get());
        if (answer.status != client_authorization::allowed) {
          BOOST_LOG(warning) << "Remote USB tunnel closing a forward: the client is no longer allowed to forward";
          finish();
        }
      }

    private:
      /** Kill the session unless it gets to the next stage in time. */
      void
      arm_deadline(std::chrono::milliseconds limit) {
        auto self = shared_from_this();
        startup_timer_.expires_after(limit);
        startup_timer_.async_wait([self](boost::system::error_code error) {
          if (error) {
            return;  // cancelled: forwarding started or the session ended
          }
          if (self->authenticated_.load()) {
            BOOST_LOG(warning) << "Remote USB tunnel startup timed out";
          } else {
            BOOST_LOG(debug) << "Remote USB tunnel dropped a connection that did not finish in time";
          }
          self->abort();
        });
      }

      void
      read_handshake() {
        auto self = shared_from_this();
        asio::async_read_until(stream_,
          asio::dynamic_buffer(handshake_, kMaxHandshakeBytes), '\n',
          [self](boost::system::error_code error, std::size_t) {
            if (error) {
              // A client that vanishes before completing the handshake, or one
              // that sends more than the cap without a newline, is closed
              // without an answer.
              self->finish();
              return;
            }
            self->handle_handshake_line();
          });
      }

      void
      handle_handshake_line() {
        /* async_read_until only completes after the delimiter, so the
         * newline is always present here; overflow is rejected by the
         * bounded dynamic_buffer's read error path instead. */
        const auto newline = handshake_.find('\n');
        if (newline == std::string::npos) {
          return;
        }

        std::string op, token, busid;
        try {
          const auto request = nlohmann::json::parse(handshake_.substr(0, newline));
          op = request.value("op", std::string {});
          token = request.value("token", std::string {});
          busid = request.value("busid", std::string {});
        }
        catch (const std::exception &) {
          reply_error("malformed handshake");
          return;
        }

        if (op != "forward") {
          reply_error("unknown operation");
          return;
        }
        if (!tokens_equal(token, config_.session_token)) {
          BOOST_LOG(warning) << "Remote USB tunnel rejected a mismatched session token";
          reply_error("unauthorized");
          return;
        }
        // Wire-level charset first (what the client enforces), then the numeric shape
        // that is safe to place on a command line.
        if (!valid_busid_charset(busid) || !valid_usbip_busid_shape(busid)) {
          reply_error("invalid busid");
          return;
        }

        // The token is shared by every paired client, so it proves nothing about who
        // is asking. Ask again, for the certificate this connection presented.
        const auto answer = peer_cert_ ? config_.authorize_client(peer_cert_.get()) : authorization_result {};
        switch (answer.status) {
          case client_authorization::allowed:
            break;
          case client_authorization::forbidden:
            BOOST_LOG(warning) << "Remote USB tunnel refused a client without the USB forwarding permission";
            reply_error("forbidden");
            return;
          case client_authorization::no_stream:
            BOOST_LOG(warning) << "Remote USB tunnel refused a client without an active stream";
            reply_error("no active stream");
            return;
          case client_authorization::not_paired:
          default:
            BOOST_LOG(warning) << "Remote USB tunnel refused a certificate that is no longer paired";
            reply_error("unauthorized");
            return;
        }
        // The certificate stays: every forward is authorized again on a timer.
        if (answer.client_id.empty()) {
          reply_error("unauthorized");
          return;
        }
        if (config_.admit_authenticated && !config_.admit_authenticated()) {
          reply_error("too many sessions");
          return;
        }
        client_id_ = answer.client_id;
        busid_ = busid;
        since_unix_ = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        authenticated_ = true;

        // One forward per device and client: the same bus id number on two different clients is
        // two different devices.
        const auto slot_key = client_id_ + '\n' + busid;
        if (config_.acquire_device_slot && !config_.acquire_device_slot(slot_key)) {
          reply_error("device already forwarded");
          return;
        }
        slot_busid_ = slot_key;

        handshake_.erase(0, newline + 1);

        open_local_endpoint(busid);
      }

      /** Bind an ephemeral loopback port for usbip-win2 to attach to. */
      void
      open_local_endpoint(const std::string &busid) {
        boost::system::error_code error;
        local_acceptor_.open(tcp::v4(), error);
        if (!error) {
          local_acceptor_.bind(
            tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0), error);
        }
        if (!error) {
          local_acceptor_.listen(1, error);
        }
        if (error) {
          reply_error("cannot open loopback endpoint");
          return;
        }

        local_port_ = local_acceptor_.local_endpoint().port();
        request_local_ = usbip_host_request {
          .server_endpoint = endpoint { "127.0.0.1", local_port_, busid },
        };

        // Arm the accept before launching the helper. Attach cannot complete
        // until its USB/IP import/enumeration traffic crosses the tunnel.
        accept_local();
        request_attach();
      }

      void
      request_attach() {
        auto self = shared_from_this();
        attach_operation_ = controller_.attach(request_local_,
          [self](usbip_host_result result) {
            // The completion fires on a controller worker thread; hop back
            // onto the service thread so all socket writes stay serialized.
            asio::post(self->stream_.get_executor(),
              [self, result = std::move(result)]() mutable {
                self->finish_attach(std::move(result));
              });
          });
        // Even a synchronous rejection invokes the completion above.
      }

      void
      finish_attach(usbip_host_result result) {
        attach_operation_ = 0;
        if (finished_.load()) {
          /* The session ended while this attach was in flight, so finish() could
           * not release the device slot yet: whatever this attach produced still
           * has to be detached, and the slot may only be released after that -
           * releasing it earlier lets a re-share start a new attach while this
           * detach is running. */
          auto release_slot = config_.release_device_slot;
          auto busid = slot_busid_;
          if (result.binding) {
            controller_.detach(*result.binding, [release_slot, busid](usbip_host_result detached) {
              if (!detached.ok()) {
                BOOST_LOG(warning) << "Remote USB tunnel detach reported: " << detached.detail;
              }
              if (release_slot && !busid.empty()) {
                release_slot(busid);
              }
            });
          }
          else if (release_slot && !busid.empty()) {
            release_slot(busid);
          }
          return;
        }
        if (!result.ok() || !result.binding) {
          BOOST_LOG(warning) << "Remote USB tunnel usbip attach failed: " << result.detail;
          reply_error("usbip attach failed");
          return;
        }
        binding_ = *result.binding;
        if (ready_sent_) {
          startup_timer_.cancel();
        }
        BOOST_LOG(info) << "Remote USB tunnel attached busid "
                        << binding_->server_endpoint.busid
                        << " at hub port " << binding_->hub_port;
      }

      /**
       * Whether a connection to the attach listener comes from the one party
       * allowed to make it: the usbip-win2 driver, which connects from the
       * kernel and is therefore attributed to System.  Any other local process
       * could otherwise race the driver and take the client's USB stream.
       */
      bool
      attach_peer_allowed(const tcp::socket &socket) {
        boost::system::error_code error;
        const auto remote = socket.remote_endpoint(error);
        if (error || !remote.address().is_v4() || !remote.address().is_loopback()) {
          BOOST_LOG(warning) << "Remote USB tunnel closed an attach connection with no loopback peer";
          return false;
        }
        const auto owner = config_.attach_peer_pid_lookup(remote.port(), local_port_);
        if (!owner) {
          BOOST_LOG(warning) << "Remote USB tunnel closed an attach connection whose owning process could not be determined";
          return false;
        }
        if (*owner != config_.attach_peer_pid) {
          BOOST_LOG(warning) << "Remote USB tunnel closed an attach connection from process " << *owner
                             << " (expected " << config_.attach_peer_pid << ")";
          return false;
        }
        return true;
      }

      void
      accept_local() {
        auto self = shared_from_this();
        local_acceptor_.async_accept(
          [self](boost::system::error_code error, tcp::socket socket) {
            if (self->finished_.load() || self->error_pending_) {
              return;
            }
            if (error) {
              if (error != asio::error::operation_aborted) {
                self->reply_error("usbip attach did not connect");
              }
              return;
            }
            if (!self->attach_peer_allowed(socket)) {
              // Closes on scope exit. Keep waiting for the real connector until
              // the startup deadline runs out.
              boost::system::error_code ignored;
              socket.close(ignored);
              self->accept_local();
              return;
            }

            // Exactly one connection is accepted per attach: stop listening now.
            boost::system::error_code ignored;
            self->local_acceptor_.close(ignored);

            self->local_ = std::make_unique<tcp::socket>(std::move(socket));
            self->raw_stream_ = true;
            asio::async_write(self->stream_, asio::buffer(self->ready_line_),
              [self](boost::system::error_code error, std::size_t) {
                if (self->finished_.load()) return;
                if (error) {
                  self->finish();
                  return;
                }
                BOOST_LOG(info) << "Remote USB tunnel forwarding busid "
                                << self->request_local_.server_endpoint.busid;
                self->ready_sent_ = true;
                if (self->binding_) {
                  self->startup_timer_.cancel();
                }
                self->flush_handshake_tail();
                self->pump_local_to_remote();
              });
          });
      }

      void
      flush_handshake_tail() {
        if (handshake_.empty()) {
          pump_remote_to_local();
          return;
        }
        auto self = shared_from_this();
        asio::async_write(*local_, asio::buffer(handshake_),
          [self](boost::system::error_code error, std::size_t) {
            if (self->finished_.load()) return;
            if (error) {
              self->finish();
              return;
            }
            self->handshake_.clear();
            self->pump_remote_to_local();
          });
      }

      void
      pump_remote_to_local() {
        auto self = shared_from_this();
        stream_.async_read_some(asio::buffer(remote_buffer_),
          [self](boost::system::error_code error, std::size_t bytes) {
            if (self->finished_.load()) return;
            if (error) {
              self->finish();
              return;
            }
            asio::async_write(*self->local_,
              asio::buffer(self->remote_buffer_, bytes),
              [self](boost::system::error_code error, std::size_t) {
                if (self->finished_.load()) return;
                if (error) {
                  self->finish();
                  return;
                }
                self->pump_remote_to_local();
              });
          });
      }

      void
      pump_local_to_remote() {
        auto self = shared_from_this();
        local_->async_read_some(asio::buffer(local_buffer_),
          [self](boost::system::error_code error, std::size_t bytes) {
            if (self->finished_.load()) return;
            if (error) {
              self->finish();
              return;
            }
            asio::async_write(self->stream_,
              asio::buffer(self->local_buffer_, bytes),
              [self](boost::system::error_code error, std::size_t) {
                if (self->finished_.load()) return;
                if (error) {
                  self->finish();
                  return;
                }
                self->pump_local_to_remote();
              });
          });
      }

      void
      reply_error(const std::string &reason) {
        if (finished_.load() || error_pending_) return;
        // Once ready has begun, the peer treats every byte as USB/IP. A late
        // attach failure must close the stream, never inject another JSON line.
        if (raw_stream_) {
          finish();
          return;
        }
        error_pending_ = true;
        // Keep the deadline until the error write finishes: the peer may stop reading.
        auto self = shared_from_this();
        // The buffer must outlive async_write, which does not own it.
        const auto line = std::make_shared<const std::string>(
          (nlohmann::json { { "op", "error" }, { "reason", reason } }).dump() + "\n");
        asio::async_write(stream_, asio::buffer(*line),
          [self, line](boost::system::error_code, std::size_t) {
            boost::system::error_code ignored;
            self->stream_.lowest_layer().shutdown(tcp::socket::shutdown_both, ignored);
            self->finish();
          });
      }

      /** Tear both sockets down and detach the usbip-win2 binding. */
      void
      finish() {
        if (finished_.exchange(true)) {
          return;
        }
        boost::system::error_code ignored;
        startup_timer_.cancel();
        local_acceptor_.close(ignored);
        if (attach_operation_ != 0) {
          controller_.cancel(attach_operation_);
        }
        if (local_) {
          local_->close(ignored);
        }
        stream_.lowest_layer().close(ignored);

        if (binding_) {
          /* Fire-and-forget on the controller's worker, but the device stays
           * claimed until that detach completes: releasing the slot here let a
           * re-share of the same device start a new attach while this detach
           * was still in flight, and two operations on one usbip-win2 port left
           * the driver wedged - every later attach and detach then timed out.
           * The callback must not touch this session, which is already gone by
           * then; it only reports and releases the slot. */
          auto release_slot = config_.release_device_slot;
          auto busid = slot_busid_;
          controller_.detach(*binding_, [release_slot, busid](usbip_host_result result) {
            if (!result.ok()) {
              BOOST_LOG(warning) << "Remote USB tunnel detach reported: " << result.detail;
            }
            if (release_slot && !busid.empty()) {
              release_slot(busid);
            }
          });
          binding_.reset();
          slot_busid_.clear();
        }
        else if (attach_operation_ != 0) {
          /* An attach is still in flight, so this session cannot tell yet what
           * has to be detached: finish_attach runs after it and releases the
           * slot once that detach is done. Releasing it here would let a
           * re-share of the same device start while the detach is still
           * running, which is what wedges the usbip-win2 port. */
        }
        else if (!slot_busid_.empty()) {
          /* Nothing was attached and nothing is on its way. */
          if (config_.release_device_slot) {
            config_.release_device_slot(slot_busid_);
          }
          slot_busid_.clear();
        }
      }

      ssl::stream<tcp::socket> stream_;
      usbip_host_controller &controller_;
      reverse_tunnel_config config_;
      /** The certificate the TLS layer accepted; kept so the forward can be authorized again. */
      x509_ptr peer_cert_ { nullptr, &X509_free };
      std::string remote_address_;
      std::string client_id_;
      std::string busid_;
      std::int64_t since_unix_ { 0 };
      std::atomic_bool authenticated_ { false };

      tcp::acceptor local_acceptor_ { stream_.get_executor() };
      std::uint16_t local_port_ { 0 };
      std::unique_ptr<tcp::socket> local_;
      usbip_host_request request_local_;
      usbip_host_controller::operation_id attach_operation_ { 0 };
      std::string slot_busid_;
      std::optional<usbip_host_binding> binding_;

      std::string handshake_;
      const std::string ready_line_ { "{\"op\":\"ready\"}\n" };
      asio::steady_timer startup_timer_;
      std::array<std::uint8_t, 64 * 1024> remote_buffer_ {};
      std::array<std::uint8_t, 64 * 1024> local_buffer_ {};
      std::atomic_bool finished_ { false };
      bool raw_stream_ { false };
      bool ready_sent_ { false };
      bool error_pending_ { false };
    };

    using session_ptr = std::shared_ptr<tunnel_session>;

  }  // namespace

  struct reverse_tunnel_service::impl {
    explicit impl(usbip_host_controller_config config):
        controller_config(config),
        controller(std::make_unique<usbip_host_controller>(std::move(config))) {}

    asio::io_context io;
    tcp::acceptor acceptor { io };
    asio::steady_timer recheck_timer { io };
    std::unique_ptr<ssl::context> ssl_context;
    /** Kept so start() after stop() can build a fresh controller: a stopped one stays stopped. */
    usbip_host_controller_config controller_config;
    std::unique_ptr<usbip_host_controller> controller;
    reverse_tunnel_config config;
    std::atomic_bool stopping { false };
    std::atomic_bool running { false };
    std::mutex session_mutex;
    /** Live sessions, for stop() broadcast; finished ones are reaped lazily. */
    std::vector<session_ptr> sessions;
    /** (client, busid) pairs with an established tunnel; one tunnel per device and client. */
    std::unordered_set<std::string> claimed_busids;
    std::thread thread;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work;

    ~impl() {
      stop();
    }

    void
    stop() noexcept {
      running.store(false);
      if (stopping.exchange(true)) {
        return;
      }
      asio::post(io, [this] {
        boost::system::error_code ignored;
        recheck_timer.cancel();
        acceptor.close(ignored);
        const std::lock_guard lock(session_mutex);
        for (const auto &session : sessions) {
          session->abort();
        }
      });
      // Keep io alive while controller completions post their final cleanup.
      controller->stop();
      asio::post(io, [this] { work.reset(); });
      if (thread.joinable()) {
        thread.join();
      }
    }

    /** Service thread: authorize every running forward again. */
    void
    recheck_all() {
      std::vector<session_ptr> snapshot;
      {
        const std::lock_guard lock(session_mutex);
        for (const auto &session : sessions) {
          if (session->authenticated() && !session->done()) {
            snapshot.push_back(session);
          }
        }
      }
      // The authorizer may take locks of its own; do not hold ours across it.
      for (const auto &session : snapshot) {
        session->recheck();
      }
    }

    void
    arm_recheck() {
      recheck_timer.expires_after(config.recheck_interval);
      recheck_timer.async_wait([this](boost::system::error_code error) {
        if (error || stopping.load()) {
          return;
        }
        recheck_all();
        arm_recheck();
      });
    }

    void
    accept_next() {
      acceptor.async_accept(
        [this](boost::system::error_code error, tcp::socket socket) {
          if (stopping.load() || error == asio::error::operation_aborted) {
            return;
          }
          if (error) {
            BOOST_LOG(warning) << "Remote USB tunnel accept failed: " << error.message();
          }
          else {
            boost::system::error_code address_error;
            const auto remote = socket.remote_endpoint(address_error);
            const std::string address = address_error ? std::string {} : remote.address().to_string();

            const std::lock_guard lock(session_mutex);
            // Reap finished sessions so stop() only has live handles.
            sessions.erase(
              std::remove_if(sessions.begin(), sessions.end(),
                [](const session_ptr &session) { return session->done(); }),
              sessions.end());

            // Connections that have not authenticated get their own, small budget, and one
            // source address cannot take all of it. A scanner must not crowd out a client.
            std::size_t unauthenticated = 0;
            std::size_t from_this_address = 0;
            for (const auto &session : sessions) {
              if (!session->authenticated()) {
                ++unauthenticated;
                from_this_address += session->remote_address() == address ? 1 : 0;
              }
            }
            if (address_error || unauthenticated >= config.max_unauthenticated || from_this_address >= config.max_unauthenticated_per_address) {
              BOOST_LOG(debug) << "Remote USB tunnel dropped a connection: too many that have not authenticated";
            }
            else {
              const auto session = std::make_shared<tunnel_session>(
                std::move(socket), *ssl_context, *controller, address);
              sessions.push_back(session);
              session->start(config);
            }
            // Otherwise socket destruction rejects this connection before TLS
            // and per-session buffers are allocated.
          }
          if (!stopping.load()) {
            accept_next();
          }
        });
    }
  };

  reverse_tunnel_service::reverse_tunnel_service(usbip_host_controller_config controller_config):
      impl_(std::make_shared<impl>(std::move(controller_config))) {}

  reverse_tunnel_service::~reverse_tunnel_service() {
    if (impl_) {
      impl_->stop();
    }
  }

  bool
  reverse_tunnel_service::start(reverse_tunnel_config config) {
    if (impl_->running.load() || impl_->thread.joinable()) {
      BOOST_LOG(warning) << "Remote USB tunnel is already started";
      return false;
    }
    if (!config.verify_client_cert || !config.authorize_client || config.max_sessions == 0 ||
        config.max_unauthenticated == 0 || config.max_unauthenticated_per_address == 0) {
      BOOST_LOG(warning) << "Remote USB tunnel requires a certificate verifier, an authorizer and positive session limits";
      return false;
    }
    if (config.session_token.empty()) {
      BOOST_LOG(info) << "Remote USB tunnel disabled: no session token configured";
      return false;
    }
    if (config.startup_timeout <= std::chrono::milliseconds::zero()) {
      config.startup_timeout = std::chrono::seconds(12);
    }
    if (config.tls_timeout <= std::chrono::milliseconds::zero()) {
      config.tls_timeout = std::chrono::seconds(3);
    }
    if (config.recheck_interval <= std::chrono::milliseconds::zero()) {
      config.recheck_interval = std::chrono::seconds(5);
    }

    // A controller that was stopped stays stopped; a service started again needs a new one.
    if (impl_->stopping.load()) {
      impl_->controller = std::make_unique<usbip_host_controller>(impl_->controller_config);
      const std::lock_guard lock(impl_->session_mutex);
      impl_->sessions.clear();
      impl_->claimed_busids.clear();
    }
    if (!impl_->controller->backend_supported()) {
      BOOST_LOG(info) << "Remote USB tunnel disabled: no host USB/IP backend on this platform";
      return false;
    }

    impl_->config = config;
    impl_->config.acquire_device_slot =
      [impl = impl_.get()](const std::string &key) {
        const std::lock_guard lock(impl->session_mutex);
        return impl->claimed_busids.insert(key).second;
      };
    impl_->config.release_device_slot =
      [impl = impl_.get()](const std::string &key) {
        const std::lock_guard lock(impl->session_mutex);
        impl->claimed_busids.erase(key);
      };
    impl_->config.admit_authenticated =
      [impl = impl_.get()]() {
        const std::lock_guard lock(impl->session_mutex);
        std::size_t authenticated = 0;
        for (const auto &session : impl->sessions) {
          authenticated += (session->authenticated() && !session->done()) ? 1 : 0;
        }
        return authenticated < impl->config.max_sessions;
      };

    impl_->ssl_context = std::make_unique<ssl::context>(ssl::context::tls_server);
    auto *native = impl_->ssl_context->native_handle();
    if (SSL_CTX_set_min_proto_version(native, TLS1_2_VERSION) != 1) {
      BOOST_LOG(warning) << "Remote USB tunnel cannot set minimum TLS version";
      impl_->ssl_context.reset();
      return false;
    }
    // No renegotiation, no session tickets, no session cache: every connection proves its
    // certificate again, and a resumed session can never skip the verifier.
    SSL_CTX_set_options(native, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(native, 0);
    SSL_CTX_set_session_cache_mode(native, SSL_SESS_CACHE_OFF);
    static const unsigned char session_context[] = "apollovibe-usb-tunnel";
    SSL_CTX_set_session_id_context(native, session_context, sizeof(session_context) - 1);
    boost::system::error_code error;
    impl_->ssl_context->use_certificate_chain_file(config.certificate_file, error);
    if (!error) {
      impl_->ssl_context->use_private_key_file(
        config.private_key_file, ssl::context::pem, error);
    }
    if (error) {
      BOOST_LOG(warning) << "Remote USB tunnel cannot load credentials: " << error.message();
      impl_->ssl_context.reset();
      return false;
    }
    impl_->ssl_context->set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
    // Asio owns SSL_CTX app_data and deletes its callback there on destruction.
    // Use its callback API instead of replacing that slot with a foreign pointer.
    impl_->ssl_context->set_verify_callback(
      [verify = config.verify_client_cert](bool, ssl::verify_context &context) {
        X509 *peer = X509_STORE_CTX_get0_cert(context.native_handle());
        return peer != nullptr && verify && verify(peer);
      });

    const auto address = asio::ip::make_address(
      config.bind_address.empty() ? "0.0.0.0" : config.bind_address, error);
    const tcp::endpoint bound(address, config.port);
    if (!error) {
      impl_->acceptor.open(bound.protocol(), error);
    }
    // Deliberately no SO_REUSEADDR: on Windows it would let a second Apollo (or any
    // other process of this account) bind the same port and split the connections.
    // A busy port must fail the start. SO_EXCLUSIVEADDRUSE is not used either: whether
    // connections left in TIME_WAIT would then block a restart on the same port is not
    // something we could verify, and a failed restart would silently turn the feature off.
    if (!error && bound.protocol() == tcp::v6()) {
      // "::" stands for "both families" here, matching the other listeners.
      impl_->acceptor.set_option(asio::ip::v6_only(false), error);
    }
    if (!error) {
      impl_->acceptor.bind(bound, error);
    }
    if (!error) {
      impl_->acceptor.listen(16, error);
    }
    if (error) {
      BOOST_LOG(warning) << "Remote USB tunnel cannot listen on " << config.bind_address
                         << ':' << config.port << ": " << error.message();
      boost::system::error_code ignored;
      impl_->acceptor.close(ignored);
      impl_->ssl_context.reset();
      return false;
    }

    impl_->stopping.store(false);
    impl_->io.restart();
    impl_->accept_next();
    impl_->arm_recheck();
    impl_->work = std::make_unique<
      asio::executor_work_guard<asio::io_context::executor_type>>(
      impl_->io.get_executor());
    impl_->thread = std::thread([io = &impl_->io] { io->run(); });
    impl_->running.store(true);
    BOOST_LOG(info) << "Remote USB tunnel listening on "
                    << config.bind_address << ':' << config.port;
    return true;
  }

  void
  reverse_tunnel_service::stop() noexcept {
    if (impl_) {
      impl_->stop();
    }
  }

  namespace {
    /**
     * Runs @p task on the service thread and waits for its answer.
     * Nothing when the service is not running, or does not get to it in time. The shared state
     * keeps the answer slot alive if the task runs after the caller gave up.
     */
    template <class Result, class Task>
    std::optional<Result>
    run_on_service_thread(asio::io_context &io, const std::atomic_bool &running, std::chrono::milliseconds timeout, Task task) {
      if (!running.load()) {
        return std::nullopt;
      }
      auto promise = std::make_shared<std::promise<Result>>();
      auto future = promise->get_future();
      asio::post(io, [promise, task = std::move(task)]() mutable {
        try {
          promise->set_value(task());
        }
        catch (...) {
          // The caller sees "no answer"; never throw into the io loop.
        }
      });
      try {
        if (future.wait_for(timeout) != std::future_status::ready) {
          return std::nullopt;
        }
        return future.get();
      }
      catch (...) {
        return std::nullopt;  // the task was dropped (service stopping) or threw
      }
    }
  }  // namespace

  void
  reverse_tunnel_service::revoke(const std::string &client_id) {
    if (!impl_ || client_id.empty() || !impl_->running.load()) {
      return;
    }
    asio::post(impl_->io, [impl = impl_, client_id] {
      std::vector<session_ptr> matching;
      {
        const std::lock_guard lock(impl->session_mutex);
        for (const auto &session : impl->sessions) {
          if (session->authenticated() && !session->done() && session->client_id() == client_id) {
            matching.push_back(session);
          }
        }
      }
      for (const auto &session : matching) {
        BOOST_LOG(info) << "Remote USB tunnel closing a forward: access was withdrawn";
        session->abort();
      }
    });
  }

  std::optional<std::size_t>
  reverse_tunnel_service::revoke_counted(const std::string &client_id, std::chrono::milliseconds timeout) {
    if (!impl_ || client_id.empty()) {
      return std::nullopt;
    }
    return run_on_service_thread<std::size_t>(impl_->io, impl_->running, timeout, [impl = impl_, client_id]() -> std::size_t {
      std::vector<session_ptr> matching;
      {
        const std::lock_guard lock(impl->session_mutex);
        for (const auto &session : impl->sessions) {
          if (session->authenticated() && !session->done() && session->client_id() == client_id) {
            matching.push_back(session);
          }
        }
      }
      for (const auto &session : matching) {
        BOOST_LOG(info) << "Remote USB tunnel closing a forward: access was withdrawn";
        session->abort();
      }
      return matching.size();
    });
  }

  std::optional<std::vector<forward_info>>
  reverse_tunnel_service::forwards(std::chrono::milliseconds timeout) const {
    if (!impl_) {
      return std::nullopt;
    }
    return run_on_service_thread<std::vector<forward_info>>(impl_->io, impl_->running, timeout, [impl = impl_]() {
      std::vector<forward_info> result;
      const std::lock_guard lock(impl->session_mutex);
      for (const auto &session : impl->sessions) {
        if (session->authenticated() && !session->done()) {
          result.push_back(session->describe());
        }
      }
      return result;
    });
  }

  bool
  reverse_tunnel_service::running() const noexcept {
    return impl_ && impl_->running.load();
  }

  std::uint16_t
  reverse_tunnel_service::bound_port() const noexcept {
    if (!impl_ || !impl_->acceptor.is_open()) {
      return 0;
    }
    boost::system::error_code ignored;
    return impl_->acceptor.local_endpoint(ignored).port();
  }

}  // namespace remote_usb
