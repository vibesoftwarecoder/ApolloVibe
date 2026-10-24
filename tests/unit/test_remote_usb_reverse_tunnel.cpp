/**
 * @file tests/unit/test_remote_usb_reverse_tunnel.cpp
 * @brief Behaviour tests for the USB forwarding tunnel (src/remote_usb/reverse_tunnel_service.cpp).
 * @details Real TLS, real sockets on loopback, a real Boost.Asio test client with OpenSSL certificates.
 *          Nothing here runs usbip.exe, touches a driver or needs a USB device: the controller is given a
 *          fake command runner that behaves like usbip-win2 (the "kernel" end connects to the loopback
 *          listener the service opened) and records every command line it is given.
 */
#ifdef _WIN32

  #include <src/logging.h>
  #include <src/nvhttp.h>
  #include <src/remote_usb/reverse_tunnel_service.h>

  #include <algorithm>
  #include <atomic>
  #include <chrono>
  #include <condition_variable>
  #include <filesystem>
  #include <fstream>
  #include <map>
  #include <memory>
  #include <mutex>
  #include <optional>
  #include <string>
  #include <thread>
  #include <vector>

  #include <boost/asio.hpp>
  #include <boost/asio/ssl.hpp>
  #include <nlohmann/json.hpp>
  #include <openssl/evp.h>
  #include <openssl/pem.h>
  #include <openssl/ssl.h>
  #include <openssl/x509.h>

  #include <gtest/gtest.h>

  #ifdef _WIN32
    #include <windows.h>
  #endif

namespace {

  namespace asio = boost::asio;
  namespace ssl = boost::asio::ssl;
  using tcp = asio::ip::tcp;
  using namespace std::chrono_literals;
  using crypto::PERM;

  // 64 hex digits, never a value the host could generate.
  const std::string kToken = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";
  const std::string kWrongToken = "baadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00d";

  // ---- certificates ---------------------------------------------------------------------------------------

  struct identity {
    std::shared_ptr<EVP_PKEY> key;
    std::shared_ptr<X509> cert;
    std::string der;
  };

  identity make_identity(const char *common_name) {
    identity result;
    EVP_PKEY *key = EVP_EC_gen("P-256");
    EXPECT_NE(key, nullptr);
    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert), 24 * 3600);
    X509_set_pubkey(cert, key);
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    EXPECT_GT(X509_sign(cert, key, EVP_sha256()), 0);

    unsigned char *buffer = nullptr;
    const int length = i2d_X509(cert, &buffer);
    EXPECT_GT(length, 0);
    result.der.assign(reinterpret_cast<const char *>(buffer), static_cast<std::size_t>(length));
    OPENSSL_free(buffer);
    result.key.reset(key, EVP_PKEY_free);
    result.cert.reset(cert, X509_free);
    return result;
  }

  std::string der_of(X509 *cert) {
    unsigned char *buffer = nullptr;
    const int length = i2d_X509(cert, &buffer);
    if (length <= 0) {
      return {};
    }
    std::string der(reinterpret_cast<const char *>(buffer), static_cast<std::size_t>(length));
    OPENSSL_free(buffer);
    return der;
  }

  // ---- the fake usbip-win2 -----------------------------------------------------------------------------------

  struct fake_driver {
    std::mutex mutex;
    std::condition_variable condition;
    std::vector<std::vector<std::string>> calls;
    asio::io_context kernel_io;  // declared first: the sockets below must be destroyed before it
    std::map<std::string, std::unique_ptr<tcp::socket>> kernel_sockets;  // by bus id
    std::atomic<std::uint16_t> kernel_port {0};
    std::atomic<std::uint16_t> last_listener_port {0};
    std::atomic<int> next_hub_port {7};
    std::atomic<int> attach_exit_code {0};
    bool connect_as_kernel = true;
    // Called with the loopback listener port before the "kernel" connects.
    std::function<void(std::uint16_t)> before_connect;

    remote_usb::usbip_command_result run(const std::string &, const std::vector<std::string> &arguments, std::chrono::milliseconds, const std::shared_ptr<std::atomic_bool> &cancel, std::size_t) {
      {
        std::lock_guard lock(mutex);
        calls.push_back(arguments);
        condition.notify_all();
      }
      remote_usb::usbip_command_result result;
      if (arguments.size() >= 9 && arguments[2] == "attach") {
        const auto listener_port = static_cast<std::uint16_t>(std::stoi(arguments[1]));
        const std::string busid = arguments[6];
        last_listener_port = listener_port;
        if (before_connect) {
          before_connect(listener_port);
        }
        if (attach_exit_code != 0) {
          result.exit_code = attach_exit_code;
          result.standard_error = "attach failed";
          return result;
        }
        if (connect_as_kernel) {
          auto socket = std::make_unique<tcp::socket>(kernel_io);
          boost::system::error_code ec;
          socket->open(tcp::v4(), ec);
          socket->bind(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0), ec);
          kernel_port = socket->local_endpoint(ec).port();
          socket->connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), listener_port), ec);
          if (ec) {
            result.exit_code = 1;
            result.standard_error = ec.message();
            return result;
          }
          std::lock_guard lock(mutex);
          kernel_sockets[busid] = std::move(socket);
          condition.notify_all();
        }
        // The real attach returns once the import has crossed the tunnel; wait a moment, honouring cancel.
        for (int i = 0; i < 10 && !(cancel && cancel->load()); ++i) {
          std::this_thread::sleep_for(5ms);
        }
        result.exit_code = 0;
        result.standard_output = std::to_string(next_hub_port++) + "\n";
        return result;
      }
      result.exit_code = 0;
      return result;
    }

    bool wait_for_call(const std::function<bool(const std::vector<std::string> &)> &predicate, std::chrono::milliseconds limit = 3s) {
      std::unique_lock lock(mutex);
      return condition.wait_for(lock, limit, [&] {
        for (const auto &call : calls) {
          if (predicate(call)) {
            return true;
          }
        }
        return false;
      });
    }

    std::size_t count(const std::function<bool(const std::vector<std::string> &)> &predicate) {
      std::lock_guard lock(mutex);
      std::size_t total = 0;
      for (const auto &call : calls) {
        total += predicate(call) ? 1 : 0;
      }
      return total;
    }

    static bool is_attach(const std::vector<std::string> &call) {
      return call.size() > 2 && call[2] == "attach";
    }

    static bool is_detach(const std::vector<std::string> &call) {
      return !call.empty() && call[0] == "detach";
    }

    std::size_t attaches() {
      return count(is_attach);
    }

    std::size_t detaches() {
      return count(is_detach);
    }

    std::unique_ptr<tcp::socket> take_kernel(const std::string &busid) {
      // The service says "ready" the moment the kernel end connects, which can be just before the
      // fake driver has filed its socket; wait for it.
      std::unique_lock lock(mutex);
      condition.wait_for(lock, 2s, [&] { return kernel_sockets.contains(busid); });
      auto it = kernel_sockets.find(busid);
      if (it == kernel_sockets.end()) {
        return nullptr;
      }
      auto socket = std::move(it->second);
      kernel_sockets.erase(it);
      return socket;
    }
  };

  // ---- the test client -----------------------------------------------------------------------------------------

  void set_timeouts(tcp::socket &socket, DWORD milliseconds) {
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&milliseconds), sizeof(milliseconds));
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&milliseconds), sizeof(milliseconds));
  }

  struct tunnel_client {
    asio::io_context io;
    ssl::context context {ssl::context::tls_client};
    std::unique_ptr<ssl::stream<tcp::socket>> stream;
    std::string inbuf;
    boost::system::error_code last_error;

    explicit tunnel_client(const identity *id = nullptr) {
      SSL_CTX_set_min_proto_version(context.native_handle(), TLS1_2_VERSION);
      context.set_verify_mode(ssl::verify_none);  // pinning the host is the client's job, not under test here
      if (id) {
        SSL_CTX_use_certificate(context.native_handle(), id->cert.get());
        SSL_CTX_use_PrivateKey(context.native_handle(), id->key.get());
      }
    }

    // True when TCP and the TLS handshake completed. With TLS 1.3 a rejected client certificate only shows up on the next read.
    bool connect(std::uint16_t port, DWORD timeout_ms = 3000, SSL_SESSION *resume = nullptr) {
      stream = std::make_unique<ssl::stream<tcp::socket>>(io, context);
      if (resume) {
        SSL_set_session(stream->native_handle(), resume);
      }
      auto &socket = stream->next_layer();
      socket.connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), port), last_error);
      if (last_error) {
        return false;
      }
      set_timeouts(socket, timeout_ms);
      stream->handshake(ssl::stream_base::client, last_error);
      return !last_error;
    }

    bool send(const std::string &data) {
      asio::write(*stream, asio::buffer(data), last_error);
      return !last_error;
    }

    bool send_forward(const std::string &token, const std::string &busid) {
      return send((nlohmann::json {{"op", "forward"}, {"token", token}, {"busid", busid}}).dump() + "\n");
    }

    // One line without the newline, or nullopt on error, timeout or close.
    std::optional<std::string> read_line() {
      for (;;) {
        const auto newline = inbuf.find('\n');
        if (newline != std::string::npos) {
          auto line = inbuf.substr(0, newline);
          inbuf.erase(0, newline + 1);
          return line;
        }
        if (!fill()) {
          return std::nullopt;
        }
      }
    }

    std::optional<std::string> read_exact(std::size_t count) {
      while (inbuf.size() < count) {
        if (!fill()) {
          return std::nullopt;
        }
      }
      auto data = inbuf.substr(0, count);
      inbuf.erase(0, count);
      return data;
    }

    bool fill() {
      char chunk[4096];
      const auto bytes = stream->read_some(asio::buffer(chunk), last_error);
      if (last_error || bytes == 0) {
        return false;
      }
      inbuf.append(chunk, bytes);
      return true;
    }

    // The connection ended the way a close does (not because our own timeout expired).
    bool ended_by_peer() const {
      return last_error && last_error != asio::error::timed_out && last_error != boost::system::errc::timed_out;
    }

    void close() {
      boost::system::error_code ignored;
      if (stream) {
        stream->next_layer().close(ignored);
      }
    }
  };

  // ---- the service under test ------------------------------------------------------------------------------------

  struct client_record {
    PERM perm = PERM::_default | PERM::usb_forward;
    bool has_stream = true;
    std::string id;  // the paired client the certificate belongs to
  };

  class tunnel_fixture {
  public:
    tunnel_fixture():
        server(make_identity("server")),
        alice(make_identity("alice")),
        bob(make_identity("bob")),
        mallory(make_identity("mallory")) {
      static std::atomic<int> counter {0};
      directory = std::filesystem::temp_directory_path() / ("apollovibe_usb_tunnel_test_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(counter++));
      std::filesystem::create_directories(directory);
      write_pem();
      paired[alice.der].id = "alice-id";
      paired[bob.der].id = "bob-id";
    }

    ~tunnel_fixture() {
      if (service) {
        service->stop();
      }
      std::error_code ignored;
      std::filesystem::remove_all(directory, ignored);
    }

    remote_usb::usbip_host_controller_config controller_config() {
      remote_usb::usbip_host_controller_config config;
      config.executable = "C:\\Fake\\USBip\\usbip.exe";
      config.executable_validator = [](const std::string &) { return remote_usb::executable_check {true, {}}; };
      config.attach_timeout = 5s;
      config.detach_timeout = 5s;
      config.command_runner = [this](const std::string &executable, const std::vector<std::string> &arguments, std::chrono::milliseconds timeout, const std::shared_ptr<std::atomic_bool> &cancel, std::size_t max) {
        return driver.run(executable, arguments, timeout, cancel, max);
      };
      return config;
    }

    remote_usb::reverse_tunnel_config tunnel_config() {
      remote_usb::reverse_tunnel_config config;
      config.bind_address = "127.0.0.1";
      config.port = 0;
      config.certificate_file = (directory / "server.pem").string();
      config.private_key_file = (directory / "server.key").string();
      config.session_token = kToken;
      config.startup_timeout = 5s;
      config.tls_timeout = 2s;
      config.recheck_interval = 150ms;
      config.verify_client_cert = [this](X509 *cert) {
        ++verify_calls;
        bool known;
        {
          std::lock_guard lock(state_mutex);
          known = paired.contains(der_of(cert));
        }
        if (known && on_verified) {
          on_verified();  // lets a test change things at the moment TLS has just accepted the certificate
        }
        return known;
      };
      config.authorize_client = [this](X509 *cert) {
        ++authorize_calls;
        if (before_authorize) {
          before_authorize();
        }
        client_record record;
        {
          std::lock_guard lock(state_mutex);
          const auto it = paired.find(der_of(cert));
          if (it == paired.end()) {
            return remote_usb::authorization_result {};
          }
          record = it->second;
        }
        return remote_usb::authorization_result {nvhttp::usb_forwarding_client_authorization(record.perm, require_stream, record.has_stream, record.id), record.id};
      };
      // Pretend to be the kernel: only the fake driver's own connection comes from "System".
      config.attach_peer_pid_lookup = [this](std::uint16_t peer_port, std::uint16_t) -> std::optional<std::uint32_t> {
        ++lookups;
        if (lookup_unknown) {
          return std::nullopt;
        }
        if (peer_port == driver.kernel_port.load()) {
          return 4u;
        }
        return 1234u;
      };
      return config;
    }

    bool start(std::function<void(remote_usb::reverse_tunnel_config &)> adjust = {}) {
      service = std::make_unique<remote_usb::reverse_tunnel_service>(controller_config());
      auto config = tunnel_config();
      if (adjust) {
        adjust(config);
      }
      return service->start(std::move(config));
    }

    std::uint16_t port() const {
      return service->bound_port();
    }

    // Connect with a certificate and ask to forward; returns the first line of the answer.
    std::optional<std::string> forward(const identity *id, const std::string &token, const std::string &busid) {
      tunnel_client client(id);
      if (!client.connect(port()) || !client.send_forward(token, busid)) {
        return std::nullopt;
      }
      return client.read_line();
    }

    void set_client(const identity &id, client_record record) {
      std::lock_guard lock(state_mutex);
      record.id = paired[id.der].id;
      paired[id.der] = record;
    }

    void unpair(const identity &id) {
      std::lock_guard lock(state_mutex);
      paired.erase(id.der);
    }

    identity server, alice, bob, mallory;
    std::filesystem::path directory;
    fake_driver driver;
    std::unique_ptr<remote_usb::reverse_tunnel_service> service;
    std::mutex state_mutex;
    std::map<std::string, client_record> paired;
    std::atomic<int> verify_calls {0};
    std::atomic<int> authorize_calls {0};
    std::atomic<int> lookups {0};
    std::atomic<bool> lookup_unknown {false};
    bool require_stream = true;
    std::function<void()> on_verified;
    std::function<void()> before_authorize;

  private:
    void write_pem() {
      {
        std::FILE *file = std::fopen((directory / "server.pem").string().c_str(), "wb");
        ASSERT_NE(file, nullptr);
        PEM_write_X509(file, server.cert.get());
        std::fclose(file);
      }
      {
        std::FILE *file = std::fopen((directory / "server.key").string().c_str(), "wb");
        ASSERT_NE(file, nullptr);
        PEM_write_PrivateKey(file, server.key.get(), nullptr, nullptr, 0, nullptr, nullptr);
        std::fclose(file);
      }
    }
  };

  std::string error_reason(const std::optional<std::string> &line) {
    if (!line) {
      return "<no answer>";
    }
    try {
      const auto body = nlohmann::json::parse(*line);
      if (body.value("op", "") == "error") {
        return body.value("reason", "");
      }
      return "<" + body.value("op", "?") + ">";
    } catch (...) {
      return "<unparseable>";
    }
  }

  bool is_ready(const std::optional<std::string> &line) {
    return line && *line == "{\"op\":\"ready\"}";
  }

  std::string read_log_file() {
    logging::log_flush();
    std::ifstream input("test_sunshine.log", std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  }

}  // namespace

// ---- the working path ------------------------------------------------------------------------------------------

TEST(RemoteUsbTunnel, ForwardsBytesBothWaysAfterReady) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());

  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  EXPECT_TRUE(is_ready(client.read_line()));

  // usbip.exe was asked for exactly the documented command, for this bus id and a loopback port.
  ASSERT_TRUE(fixture.driver.wait_for_call(fake_driver::is_attach));
  {
    std::lock_guard lock(fixture.driver.mutex);
    const auto &call = fixture.driver.calls.front();
    ASSERT_EQ(call.size(), 9u);
    EXPECT_EQ(call[0], "--tcp-port");
    EXPECT_EQ(call[2], "attach");
    EXPECT_EQ(call[3], "--remote");
    EXPECT_EQ(call[4], "127.0.0.1");
    EXPECT_EQ(call[5], "--bus-id");
    EXPECT_EQ(call[6], "1-2");
    EXPECT_EQ(call[7], "--once");
    EXPECT_EQ(call[8], "--terse");
  }

  auto kernel = fixture.driver.take_kernel("1-2");
  ASSERT_NE(kernel, nullptr);
  set_timeouts(*kernel, 3000);
  boost::system::error_code ec;

  ASSERT_TRUE(client.send("HELLO-FROM-CLIENT"));
  char received[17] = {};
  asio::read(*kernel, asio::buffer(received, 17), ec);
  ASSERT_FALSE(ec) << ec.message();
  EXPECT_EQ(std::string(received, 17), "HELLO-FROM-CLIENT");

  asio::write(*kernel, asio::buffer(std::string("HELLO-FROM-KERNEL")), ec);
  ASSERT_FALSE(ec);
  const auto answer = client.read_exact(17);
  ASSERT_TRUE(answer.has_value());
  EXPECT_EQ(*answer, "HELLO-FROM-KERNEL");
}

// ---- token ---------------------------------------------------------------------------------------------------

TEST(RemoteUsbTunnel, AWrongTokenIsRefusedAndNothingIsAttached) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kWrongToken, "1-2")), "unauthorized");
  EXPECT_EQ(fixture.driver.attaches(), 0u);
}

TEST(RemoteUsbTunnel, EmptyShortAndLongTokensAreRefused) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  for (const std::string token : {std::string {}, kToken.substr(0, 63), kToken + "0", std::string(64, 'F'), kToken.substr(0, 32)}) {
    SCOPED_TRACE(token);
    EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, token, "1-2")), "unauthorized");
  }
  EXPECT_EQ(fixture.driver.attaches(), 0u);
}

TEST(RemoteUsbTunnel, TheTokenIsCheckedBeforeTheClientIsAuthorized) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  const auto before = fixture.authorize_calls.load();
  // A client that lacks the permission, with a wrong token: the answer must not reveal the permission state.
  fixture.set_client(fixture.alice, {PERM::_default, true});
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kWrongToken, "1-2")), "unauthorized");
  EXPECT_EQ(fixture.authorize_calls.load(), before);
}

TEST(RemoteUsbTunnel, MissingFieldsAndWrongOperationsAreRefused) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  const std::string lines[] = {
    "{}\n",
    "not json\n",
    "{\"op\":\"forward\"}\n",
    "{\"op\":\"attach\",\"token\":\"" + kToken + "\",\"busid\":\"1-2\"}\n",
    "{\"op\":\"forward\",\"token\":5,\"busid\":\"1-2\"}\n",
    "[1,2,3]\n",
    "\n",
  };
  for (const auto &line : lines) {
    SCOPED_TRACE(line);
    tunnel_client client(&fixture.alice);
    ASSERT_TRUE(client.connect(fixture.port()));
    ASSERT_TRUE(client.send(line));
    const auto reason = error_reason(client.read_line());
    EXPECT_NE(reason, "<ready>");
    EXPECT_NE(reason, "<no answer>");
  }
  EXPECT_EQ(fixture.driver.attaches(), 0u);
}

// ---- bus id --------------------------------------------------------------------------------------------------

TEST(RemoteUsbTunnel, AnInvalidBusIdIsRefusedBeforeAnyCommandRuns) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  const std::string bad_ids[] = {
    "", "--help", "-1-2", "1-2;calc", "1-2 --x", "usb", "1-9:0", "..\\1-2", "1-2\"", std::string(32, '1'), "1-2\r", "0-1", "%TEMP%",
  };
  for (const auto &busid : bad_ids) {
    SCOPED_TRACE(busid);
    EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kToken, busid)), "invalid busid");
  }
  EXPECT_EQ(fixture.driver.attaches(), 0u);
  EXPECT_EQ(fixture.driver.count([](const auto &) { return true; }), 0u);
}

// ---- who may connect ---------------------------------------------------------------------------------------

TEST(RemoteUsbTunnel, AConnectionWithoutAClientCertificateGetsNothing) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client client(nullptr);
  // With TLS 1.3 the handshake may "succeed" on the client side; the refusal then arrives on the first read.
  if (client.connect(fixture.port())) {
    client.send_forward(kToken, "1-2");
    const auto line = client.read_line();
    EXPECT_FALSE(line.has_value()) << *line;
  }
  EXPECT_EQ(fixture.driver.attaches(), 0u);
  EXPECT_EQ(fixture.authorize_calls.load(), 0);
}

TEST(RemoteUsbTunnel, ACertificateThatIsNotPairedGetsNothing) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.mallory);
  if (client.connect(fixture.port())) {
    client.send_forward(kToken, "1-2");
    const auto line = client.read_line();
    EXPECT_FALSE(line.has_value()) << *line;
  }
  EXPECT_GT(fixture.verify_calls.load(), 0) << "the verifier was never asked, so this proved nothing";
  EXPECT_EQ(fixture.driver.attaches(), 0u);
  EXPECT_EQ(fixture.authorize_calls.load(), 0);
}

TEST(RemoteUsbTunnel, AValidTokenAndAPairedCertificateWithoutThePermissionIsForbidden) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  fixture.set_client(fixture.alice, {PERM::_default, true});
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kToken, "1-2")), "forbidden");
  fixture.set_client(fixture.alice, {PERM::_all, true});  // everything a first-paired client gets
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kToken, "1-2")), "forbidden");
  EXPECT_EQ(fixture.driver.attaches(), 0u);
  EXPECT_GE(fixture.authorize_calls.load(), 2);
}

TEST(RemoteUsbTunnel, APermittedClientWithoutAnActiveStreamIsRefusedWhenAStreamIsRequired) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  fixture.set_client(fixture.alice, {PERM::_default | PERM::usb_forward, false});
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kToken, "1-2")), "no active stream");
  EXPECT_EQ(fixture.driver.attaches(), 0u);
}

TEST(RemoteUsbTunnel, TheStreamIsNotNeededWhenTheHostDoesNotRequireIt) {
  tunnel_fixture fixture;
  fixture.require_stream = false;
  ASSERT_TRUE(fixture.start());
  fixture.set_client(fixture.alice, {PERM::_default | PERM::usb_forward, false});
  EXPECT_TRUE(is_ready(fixture.forward(&fixture.alice, kToken, "1-2")));
}

TEST(RemoteUsbTunnel, ThePermissionIsCheckedAtHandshakeTimeNotWhenTheConnectionOpened) {
  tunnel_fixture fixture;
  fixture.on_verified = [&fixture] { fixture.set_client(fixture.alice, {PERM::_default, true}); };  // revoked just after TLS accepts her
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));  // TLS passes: alice has the permission right now
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  EXPECT_EQ(error_reason(client.read_line()), "forbidden");
  EXPECT_EQ(fixture.driver.attaches(), 0u);
}

TEST(RemoteUsbTunnel, ACertificateUnpairedAfterTlsIsRefusedAtHandshakeTime) {
  tunnel_fixture fixture;
  fixture.before_authorize = [&fixture] { fixture.unpair(fixture.alice); };  // unpaired after TLS, before the handshake is judged
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  EXPECT_EQ(error_reason(client.read_line()), "unauthorized");
  EXPECT_EQ(fixture.driver.attaches(), 0u);
}

TEST(RemoteUsbTunnel, TheTokenIsTheSameForEveryoneSoTheOtherClientIsStillChecked) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  fixture.set_client(fixture.bob, {PERM::_default, true});  // bob has the token too, but not the permission
  EXPECT_EQ(error_reason(fixture.forward(&fixture.bob, kToken, "1-2")), "forbidden");
  EXPECT_TRUE(is_ready(fixture.forward(&fixture.alice, kToken, "1-3")));
}

// ---- bounds ------------------------------------------------------------------------------------------------

TEST(RemoteUsbTunnel, AHandshakeLongerThanTheCapIsClosedWithoutAnAnswer) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  {
    tunnel_client client(&fixture.alice);
    ASSERT_TRUE(client.connect(fixture.port()));
    client.send(std::string(5000, 'a'));  // no newline
    EXPECT_FALSE(client.read_line().has_value());
    EXPECT_TRUE(client.ended_by_peer()) << client.last_error.message();
  }
  {
    // A complete, otherwise valid line that is one byte over 4096 bytes including the newline.
    nlohmann::json body {{"op", "forward"}, {"token", kToken}, {"busid", "1-2"}, {"pad", ""}};
    const auto base = body.dump().size() + 1;
    body["pad"] = std::string(4097 - base, 'p');
    const auto line = body.dump() + "\n";
    ASSERT_EQ(line.size(), 4097u);
    tunnel_client client(&fixture.alice);
    ASSERT_TRUE(client.connect(fixture.port()));
    client.send(line);
    EXPECT_FALSE(client.read_line().has_value());
    EXPECT_TRUE(client.ended_by_peer()) << client.last_error.message();
  }
  EXPECT_EQ(fixture.driver.attaches(), 0u);
}

TEST(RemoteUsbTunnel, AHandshakeOfExactlyTheCapIsStillRead) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  nlohmann::json body {{"op", "forward"}, {"token", kWrongToken}, {"busid", "1-2"}, {"pad", ""}};
  const auto base = body.dump().size() + 1;
  body["pad"] = std::string(4096 - base, 'p');
  const auto line = body.dump() + "\n";
  ASSERT_EQ(line.size(), 4096u);
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  client.send(line);
  EXPECT_EQ(error_reason(client.read_line()), "unauthorized");
}

TEST(RemoteUsbTunnel, AConnectionThatNeverSendsTheHandshakeIsClosedAtTheDeadline) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start([](auto &config) { config.startup_timeout = 400ms; }));
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port(), 4000));
  const auto started = std::chrono::steady_clock::now();
  EXPECT_FALSE(client.read_line().has_value());
  const auto waited = std::chrono::steady_clock::now() - started;
  EXPECT_TRUE(client.ended_by_peer()) << "our own read timeout fired, the host never closed: " << client.last_error.message();
  EXPECT_LT(waited, 3s);
  EXPECT_GE(waited, 300ms) << "closed before the deadline";
}

TEST(RemoteUsbTunnel, ATlsConnectionThatNeverFinishesTheHandshakeIsClosed) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start([](auto &config) {
    config.startup_timeout = 400ms;
    config.tls_timeout = 400ms;
  }));
  asio::io_context io;
  tcp::socket socket(io);
  boost::system::error_code ec;
  socket.connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), fixture.port()), ec);
  ASSERT_FALSE(ec);
  set_timeouts(socket, 4000);
  char byte;
  const auto started = std::chrono::steady_clock::now();
  asio::read(socket, asio::buffer(&byte, 1), ec);  // the host sends nothing first, so this ends only when it closes us
  EXPECT_TRUE(ec);
  EXPECT_NE(ec, asio::error::timed_out);
  EXPECT_LT(std::chrono::steady_clock::now() - started, 3s);
}

// Silent peers come from 127.0.0.2 so that the one legitimate client (127.0.0.1) is a different source address.
std::unique_ptr<tcp::socket> connect_from(asio::io_context &io, const char *source, std::uint16_t port) {
  auto socket = std::make_unique<tcp::socket>(io);
  boost::system::error_code ec;
  socket->open(tcp::v4(), ec);
  socket->bind(tcp::endpoint(asio::ip::make_address_v4(source), 0), ec);
  socket->connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), port), ec);
  if (ec) {
    return nullptr;
  }
  return socket;
}

// True when the peer has closed the connection (read ends with eof/reset) within the limit.
bool closed_within(tcp::socket &socket, DWORD milliseconds) {
  set_timeouts(socket, milliseconds);
  char byte;
  boost::system::error_code ec;
  asio::read(socket, asio::buffer(&byte, 1), ec);
  return ec && ec != asio::error::timed_out;
}

TEST(RemoteUsbTunnel, SilentPeersDoNotKeepALegitimateClientOut) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start([](auto &config) {
    config.max_unauthenticated = 6;
    config.max_unauthenticated_per_address = 3;
    config.tls_timeout = 5s;
  }));

  asio::io_context io;
  std::vector<std::unique_ptr<tcp::socket>> silent;
  for (int i = 0; i < 24; ++i) {
    if (auto socket = connect_from(io, "127.0.0.2", fixture.port())) {
      silent.push_back(std::move(socket));
    }
  }
  ASSERT_GE(silent.size(), 20u) << "the test could not open its silent peers";
  std::this_thread::sleep_for(200ms);

  // 24 silent connections from one address: the service holds three and drops the rest.
  tunnel_client legitimate(&fixture.alice);
  ASSERT_TRUE(legitimate.connect(fixture.port(), 3000)) << "silent peers crowded out a working client";
  ASSERT_TRUE(legitimate.send_forward(kToken, "1-2"));
  EXPECT_TRUE(is_ready(legitimate.read_line()));
}

TEST(RemoteUsbTunnel, OneAddressCannotHoldMoreThanItsShareOfUnauthenticatedConnections) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start([](auto &config) {
    config.max_unauthenticated = 50;
    config.max_unauthenticated_per_address = 2;
    config.tls_timeout = 10s;
  }));

  asio::io_context io;
  std::vector<std::unique_ptr<tcp::socket>> peers;
  for (int i = 0; i < 6; ++i) {
    auto socket = connect_from(io, "127.0.0.2", fixture.port());
    ASSERT_NE(socket, nullptr);
    peers.push_back(std::move(socket));
    std::this_thread::sleep_for(30ms);  // let the service decide before the next one arrives
  }
  std::size_t dropped = 0;
  for (std::size_t i = 2; i < peers.size(); ++i) {
    dropped += closed_within(*peers[i], 500) ? 1 : 0;
  }
  EXPECT_EQ(dropped, 4u) << "peers beyond the per-address share were not turned away";
  EXPECT_FALSE(closed_within(*peers[0], 200)) << "a connection inside the share was dropped";
}

TEST(RemoteUsbTunnel, TheTotalOfUnauthenticatedConnectionsIsBounded) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start([](auto &config) {
    config.max_unauthenticated = 3;
    config.max_unauthenticated_per_address = 3;
    config.tls_timeout = 10s;
  }));
  asio::io_context io;
  std::vector<std::unique_ptr<tcp::socket>> peers;
  const char *sources[] = {"127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6"};
  for (const auto *source : sources) {
    auto socket = connect_from(io, source, fixture.port());
    ASSERT_NE(socket, nullptr);
    peers.push_back(std::move(socket));
    std::this_thread::sleep_for(30ms);
  }
  EXPECT_TRUE(closed_within(*peers[3], 500));
  EXPECT_TRUE(closed_within(*peers[4], 500));
  EXPECT_FALSE(closed_within(*peers[0], 200));
}

TEST(RemoteUsbTunnel, AStalledTlsHandshakeIsDroppedQuicklyAndFreesItsPlace) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start([](auto &config) {
    config.tls_timeout = 300ms;
    config.startup_timeout = 10s;
    config.max_unauthenticated_per_address = 1;
  }));

  asio::io_context io;
  auto stalled = connect_from(io, "127.0.0.1", fixture.port());
  ASSERT_NE(stalled, nullptr);
  const char partial_hello[] = {0x16, 0x03, 0x01};  // the first bytes of a TLS record, then nothing
  boost::system::error_code ec;
  asio::write(*stalled, asio::buffer(partial_hello), ec);

  const auto started = std::chrono::steady_clock::now();
  EXPECT_TRUE(closed_within(*stalled, 3000));
  EXPECT_LT(std::chrono::steady_clock::now() - started, 2s) << "the short TLS deadline did not apply";

  // Its place is free again: the same address (a share of one) can now connect.
  tunnel_client legitimate(&fixture.alice);
  ASSERT_TRUE(legitimate.connect(fixture.port(), 3000));
  ASSERT_TRUE(legitimate.send_forward(kToken, "1-2"));
  EXPECT_TRUE(is_ready(legitimate.read_line()));
}

TEST(RemoteUsbTunnel, AuthorizedSessionsHaveTheirOwnLimit) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start([](auto &config) { config.max_sessions = 1; }));

  tunnel_client first(&fixture.alice);
  ASSERT_TRUE(first.connect(fixture.port()));
  ASSERT_TRUE(first.send_forward(kToken, "1-2"));
  ASSERT_TRUE(is_ready(first.read_line()));

  EXPECT_EQ(error_reason(fixture.forward(&fixture.bob, kToken, "1-3")), "too many sessions");
  EXPECT_EQ(fixture.driver.attaches(), 1u);
}

// ---- exclusivity and cleanup --------------------------------------------------------------------------------

TEST(RemoteUsbTunnel, OneActiveForwardPerBusId) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());

  tunnel_client first(&fixture.alice);
  ASSERT_TRUE(first.connect(fixture.port()));
  ASSERT_TRUE(first.send_forward(kToken, "1-2"));
  ASSERT_TRUE(is_ready(first.read_line()));

  // Same device, same client: refused and nothing more is attached.
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kToken, "1-2")), "device already forwarded");
  EXPECT_EQ(fixture.driver.attaches(), 1u);

  // A different device is fine.
  tunnel_client other(&fixture.alice);
  ASSERT_TRUE(other.connect(fixture.port()));
  ASSERT_TRUE(other.send_forward(kToken, "1-3"));
  EXPECT_TRUE(is_ready(other.read_line()));
  EXPECT_EQ(fixture.driver.attaches(), 2u);
}

TEST(RemoteUsbTunnel, TheSlotIsFreeAgainOnlyAfterTheDetach) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  {
    tunnel_client first(&fixture.alice);
    ASSERT_TRUE(first.connect(fixture.port()));
    ASSERT_TRUE(first.send_forward(kToken, "1-2"));
    ASSERT_TRUE(is_ready(first.read_line()));
    first.close();
  }
  ASSERT_TRUE(fixture.driver.wait_for_call(fake_driver::is_detach));
  bool again = false;
  for (int i = 0; i < 60 && !again; ++i) {
    again = is_ready(fixture.forward(&fixture.alice, kToken, "1-2"));
    if (!again) {
      std::this_thread::sleep_for(50ms);
    }
  }
  EXPECT_TRUE(again);
}

TEST(RemoteUsbTunnel, DisconnectingDetachesTheDevice) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  ASSERT_TRUE(is_ready(client.read_line()));
  ASSERT_TRUE(fixture.driver.wait_for_call(fake_driver::is_attach));
  EXPECT_EQ(fixture.driver.detaches(), 0u);

  client.close();

  ASSERT_TRUE(fixture.driver.wait_for_call([](const auto &call) { return call == std::vector<std::string> {"detach", "--port", "7"}; }))
    << "no detach for the hub port the attach reported";
  EXPECT_EQ(fixture.driver.detaches(), 1u);
}

TEST(RemoteUsbTunnel, StoppingTheServiceDetachesWhatIsStillForwarded) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  ASSERT_TRUE(is_ready(client.read_line()));
  ASSERT_TRUE(fixture.driver.wait_for_call(fake_driver::is_attach));
  // Let the attach completion register the binding before we shut down.
  std::this_thread::sleep_for(100ms);

  fixture.service->stop();

  EXPECT_FALSE(fixture.service->running());
  EXPECT_GE(fixture.driver.detaches(), 1u);
  EXPECT_TRUE(fixture.driver.wait_for_call([](const auto &call) { return call == std::vector<std::string> {"detach", "--port", "7"}; }));
  // The client is cut off.
  EXPECT_FALSE(client.read_line().has_value());
  // And nothing listens any more.
  tunnel_client late(&fixture.alice);
  EXPECT_FALSE(late.connect(fixture.port(), 1000));
}

TEST(RemoteUsbTunnel, AFailedAttachIsReportedAndLeavesNothingBehind) {
  tunnel_fixture fixture;
  fixture.driver.attach_exit_code = 1;
  ASSERT_TRUE(fixture.start());
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kToken, "1-2")), "usbip attach failed");
  // The slot was released: a later attempt reaches the driver again.
  fixture.driver.attach_exit_code = 0;
  bool again = false;
  for (int i = 0; i < 60 && !again; ++i) {
    again = is_ready(fixture.forward(&fixture.alice, kToken, "1-2"));
    if (!again) {
      std::this_thread::sleep_for(50ms);
    }
  }
  EXPECT_TRUE(again);
}

// ---- the loopback attach listener --------------------------------------------------------------------------------

TEST(RemoteUsbTunnel, ABystanderConnectingToTheAttachPortIsClosedAndTheRealDriverStillGetsIn) {
  tunnel_fixture fixture;
  std::atomic<bool> intruder_closed {false};
  std::atomic<bool> intruder_connected {false};
  fixture.driver.before_connect = [&](std::uint16_t listener_port) {
    // Another local process connects first.
    asio::io_context io;
    tcp::socket intruder(io);
    boost::system::error_code ec;
    intruder.open(tcp::v4(), ec);
    intruder.bind(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0), ec);
    intruder.connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), listener_port), ec);
    intruder_connected = !ec;
    set_timeouts(intruder, 3000);
    char byte;
    asio::read(intruder, asio::buffer(&byte, 1), ec);  // ends when the service closes it
    intruder_closed = ec == asio::error::eof || ec == asio::error::connection_reset;
  };
  ASSERT_TRUE(fixture.start());

  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  EXPECT_TRUE(is_ready(client.read_line())) << "the real connector was not accepted after the intruder was turned away";
  EXPECT_TRUE(intruder_connected);
  EXPECT_TRUE(intruder_closed) << "the intruder was left connected";
  EXPECT_GE(fixture.lookups.load(), 2) << "both connections must have been checked";

  // The data path belongs to the driver, not to the intruder.
  auto kernel = fixture.driver.take_kernel("1-2");
  ASSERT_NE(kernel, nullptr);
  set_timeouts(*kernel, 3000);
  ASSERT_TRUE(client.send("PRIVATE"));
  char received[7] = {};
  boost::system::error_code ec;
  asio::read(*kernel, asio::buffer(received, 7), ec);
  EXPECT_FALSE(ec);
  EXPECT_EQ(std::string(received, 7), "PRIVATE");
}

TEST(RemoteUsbTunnel, AConnectionWhoseOwnerCannotBeFoundIsRefused) {
  tunnel_fixture fixture;
  fixture.lookup_unknown = true;
  ASSERT_TRUE(fixture.start([](auto &config) { config.startup_timeout = 800ms; }));

  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  const auto line = client.read_line();
  EXPECT_FALSE(is_ready(line)) << "ready was sent although the connector could not be identified";
  EXPECT_GE(fixture.lookups.load(), 1);
}

TEST(RemoteUsbTunnel, OnlyTheConfiguredProcessIsAccepted) {
  tunnel_fixture fixture;
  // The "kernel" is process 4 in the fixture; require a different process and it must be refused.
  ASSERT_TRUE(fixture.start([](auto &config) {
    config.attach_peer_pid = 99;
    config.startup_timeout = 800ms;
  }));
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  EXPECT_FALSE(is_ready(client.read_line()));
}

TEST(RemoteUsbTunnel, TheAttachListenerClosesAfterTheFirstAcceptedConnection) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  ASSERT_TRUE(is_ready(client.read_line()));

  asio::io_context io;
  tcp::socket second(io);
  boost::system::error_code ec;
  second.connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), fixture.driver.last_listener_port.load()), ec);
  EXPECT_TRUE(ec) << "a second connection to the attach port was still accepted";
}

TEST(RemoteUsbTunnel, TheAttachListenerTimesOutWhenNobodyConnects) {
  tunnel_fixture fixture;
  fixture.driver.connect_as_kernel = false;
  ASSERT_TRUE(fixture.start([](auto &config) { config.startup_timeout = 500ms; }));
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port(), 4000));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  const auto started = std::chrono::steady_clock::now();
  const auto line = client.read_line();
  EXPECT_FALSE(is_ready(line));
  EXPECT_LT(std::chrono::steady_clock::now() - started, 3s);
}

TEST(RemoteUsbTunnel, TheDefaultPeerLookupFindsTheProcessThatOwnsTheConnectingSocket) {
  // Validate the instrument: with a real connection made by this very process the answer must be this process.
  asio::io_context io;
  tcp::acceptor acceptor(io, tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  const auto listener_port = acceptor.local_endpoint().port();
  tcp::socket client(io);
  client.open(tcp::v4());
  client.bind(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  const auto client_port = client.local_endpoint().port();
  client.connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), listener_port));
  tcp::socket server(io);
  acceptor.accept(server);

  const auto owner = remote_usb::tcp_loopback_peer_pid(client_port, listener_port);
  ASSERT_TRUE(owner.has_value());
  EXPECT_EQ(*owner, static_cast<std::uint32_t>(GetCurrentProcessId()));
  EXPECT_NE(*owner, 4u) << "an ordinary process must never be mistaken for System";

  // Wrong or unknown ports find nothing.
  EXPECT_FALSE(remote_usb::tcp_loopback_peer_pid(static_cast<std::uint16_t>(client_port ^ 0x4000), listener_port).has_value());
  EXPECT_FALSE(remote_usb::tcp_loopback_peer_pid(client_port, static_cast<std::uint16_t>(listener_port ^ 0x4000)).has_value());
}

TEST(RemoteUsbTunnel, TheProductionAttachCheckRefusesAnOrdinaryProcessEndToEnd) {
  // No injected lookup: the real table lookup runs, the "kernel" is this test process, and it is not System.
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start([](auto &config) {
    config.attach_peer_pid_lookup = nullptr;
    config.startup_timeout = 800ms;
  }));
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  EXPECT_FALSE(is_ready(client.read_line())) << "a connection from a user-mode process was accepted as the driver";
}

TEST(RemoteUsbTunnel, TheProductionAttachCheckAcceptsTheProcessItIsToldToExpect) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start([](auto &config) {
    config.attach_peer_pid_lookup = nullptr;
    config.attach_peer_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
  }));
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  EXPECT_TRUE(is_ready(client.read_line()));
}

// ---- the public listener ------------------------------------------------------------------------------------------

TEST(RemoteUsbTunnel, ASecondServiceCannotShareThePort) {
  tunnel_fixture first;
  ASSERT_TRUE(first.start());
  const auto port = first.port();

  tunnel_fixture second;
  EXPECT_FALSE(second.start([port](auto &config) { config.port = port; })) << "two tunnels now share one port";
  EXPECT_FALSE(second.service->running());
  EXPECT_EQ(second.service->bound_port(), 0);

  // The first one still works.
  EXPECT_TRUE(is_ready(first.forward(&first.alice, kToken, "1-2")));
}

TEST(RemoteUsbTunnel, AnotherSocketCannotShareThePortEvenWithReuseAddress) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());

  asio::io_context io;
  tcp::acceptor other(io);
  boost::system::error_code ec;
  other.open(tcp::v4(), ec);
  other.set_option(tcp::acceptor::reuse_address(true), ec);
  other.bind(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), fixture.port()), ec);
  EXPECT_TRUE(ec) << "a second socket bound to the tunnel port";
}

TEST(RemoteUsbTunnel, ABusyPortFailsClosedWithAClearLine) {
  asio::io_context io;
  tcp::acceptor squatter(io, tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
  const auto port = squatter.local_endpoint().port();

  tunnel_fixture fixture;
  EXPECT_FALSE(fixture.start([port](auto &config) { config.port = port; }));
  EXPECT_FALSE(fixture.service->running());

  const auto log = read_log_file();
  EXPECT_NE(log.find("Remote USB tunnel cannot listen on 127.0.0.1:" + std::to_string(port)), std::string::npos);
}

TEST(RemoteUsbTunnel, RefusesToStartWithoutWhatItNeeds) {
  tunnel_fixture fixture;
  EXPECT_FALSE(fixture.start([](auto &config) { config.verify_client_cert = nullptr; }));
  EXPECT_FALSE(fixture.start([](auto &config) { config.authorize_client = nullptr; }));
  EXPECT_FALSE(fixture.start([](auto &config) { config.session_token.clear(); }));
  EXPECT_FALSE(fixture.start([](auto &config) { config.max_sessions = 0; }));
  EXPECT_FALSE(fixture.start([&](auto &config) { config.certificate_file = (fixture.directory / "missing.pem").string(); }));
  EXPECT_FALSE(fixture.service->running());
}

TEST(RemoteUsbTunnel, DoesNotStartWithoutAUsableDriverBackend) {
  tunnel_fixture fixture;
  fixture.service = std::make_unique<remote_usb::reverse_tunnel_service>([&] {
    auto config = fixture.controller_config();
    config.backend = remote_usb::usbip_host_backend::unsupported;
    return config;
  }());
  EXPECT_FALSE(fixture.service->start(fixture.tunnel_config()));
  EXPECT_FALSE(fixture.service->running());
}

TEST(RemoteUsbTunnel, RejectsTlsOneOneAndOlder) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.alice);
  SSL_CTX_set_min_proto_version(client.context.native_handle(), TLS1_VERSION);
  SSL_CTX_set_max_proto_version(client.context.native_handle(), TLS1_1_VERSION);
  SSL_CTX_set_security_level(client.context.native_handle(), 0);
  // The client library may refuse to offer such a version at all; either way no session comes of it.
  if (client.connect(fixture.port())) {
    client.send_forward(kToken, "1-2");
    EXPECT_FALSE(client.read_line().has_value());
  }
  EXPECT_EQ(fixture.driver.attaches(), 0u);
}

// ---- logging ------------------------------------------------------------------------------------------------------

TEST(RemoteUsbTunnel, NeverLogsTheTokenOrWhatTheDeviceSends) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());

  fixture.forward(&fixture.alice, kWrongToken, "1-2");  // a rejected token
  fixture.set_client(fixture.bob, {PERM::_default, true});
  fixture.forward(&fixture.bob, kToken, "1-4");  // forbidden
  tunnel_client client(&fixture.alice);
  ASSERT_TRUE(client.connect(fixture.port()));
  ASSERT_TRUE(client.send_forward(kToken, "1-2"));
  ASSERT_TRUE(is_ready(client.read_line()));
  auto kernel = fixture.driver.take_kernel("1-2");
  ASSERT_NE(kernel, nullptr);
  ASSERT_TRUE(client.send("SECRET-USB-PAYLOAD-0451"));
  set_timeouts(*kernel, 3000);
  char buffer[23] = {};
  boost::system::error_code ec;
  asio::read(*kernel, asio::buffer(buffer, 23), ec);
  ASSERT_FALSE(ec);
  client.close();
  fixture.driver.wait_for_call(fake_driver::is_detach);

  const auto log = read_log_file();
  EXPECT_EQ(log.find(kToken), std::string::npos);
  EXPECT_EQ(log.find(kWrongToken), std::string::npos);
  EXPECT_EQ(log.find("SECRET-USB-PAYLOAD-0451"), std::string::npos);
  EXPECT_NE(log.find("Remote USB tunnel rejected a mismatched session token"), std::string::npos) << "the log probe saw nothing, so the checks above prove nothing";
}


// ---- access withdrawn while a forward is running -----------------------------------------------------------------

namespace {
  // alice forwards "1-2" and the fake driver has attached it.
  void establish(tunnel_fixture &fixture, tunnel_client &client) {
    ASSERT_TRUE(client.connect(fixture.port()));
    ASSERT_TRUE(client.send_forward(kToken, "1-2"));
    ASSERT_TRUE(is_ready(client.read_line()));
    ASSERT_TRUE(fixture.driver.wait_for_call(fake_driver::is_attach));
    std::this_thread::sleep_for(100ms);  // let the attach complete so a binding exists to detach
  }

  bool detached_and_closed(tunnel_fixture &fixture, tunnel_client &client) {
    const bool detached = fixture.driver.wait_for_call([](const auto &call) { return call == std::vector<std::string> {"detach", "--port", "7"}; }, 3s);
    const bool closed = !client.read_line().has_value() && client.ended_by_peer();
    return detached && closed;
  }
}  // namespace

TEST(RemoteUsbTunnel, RemovingThePermissionDetachesARunningForward) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.alice);
  establish(fixture, client);
  ASSERT_EQ(fixture.driver.detaches(), 0u);

  fixture.set_client(fixture.alice, {PERM::_default, true});

  EXPECT_TRUE(detached_and_closed(fixture, client)) << "the device stayed attached after the permission was removed";
}

TEST(RemoteUsbTunnel, UnpairingDetachesARunningForward) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.alice);
  establish(fixture, client);

  fixture.unpair(fixture.alice);

  EXPECT_TRUE(detached_and_closed(fixture, client));
}

TEST(RemoteUsbTunnel, TheStreamEndingDetachesARunningForward) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.alice);
  establish(fixture, client);

  fixture.set_client(fixture.alice, {PERM::_default | PERM::usb_forward, false});  // the stream session ended

  EXPECT_TRUE(detached_and_closed(fixture, client));
}

TEST(RemoteUsbTunnel, AForwardThatStaysAllowedKeepsWorkingAcrossRechecks) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client client(&fixture.alice);
  establish(fixture, client);
  const auto before = fixture.authorize_calls.load();
  std::this_thread::sleep_for(700ms);  // several recheck intervals
  EXPECT_GT(fixture.authorize_calls.load(), before + 1) << "the forward was never authorized again";

  auto kernel = fixture.driver.take_kernel("1-2");
  ASSERT_NE(kernel, nullptr);
  set_timeouts(*kernel, 3000);
  ASSERT_TRUE(client.send("STILL-HERE"));
  char received[10] = {};
  boost::system::error_code ec;
  asio::read(*kernel, asio::buffer(received, 10), ec);
  EXPECT_FALSE(ec);
  EXPECT_EQ(fixture.driver.detaches(), 0u);
}

TEST(RemoteUsbTunnel, RevokeCutsThatClientsForwardsAtOnceAndOnlyThatClients) {
  tunnel_fixture fixture;
  // The recheck is an hour away, so only revoke() can be what ends it.
  ASSERT_TRUE(fixture.start([](auto &config) { config.recheck_interval = std::chrono::hours(1); }));
  tunnel_client alice(&fixture.alice);
  establish(fixture, alice);
  tunnel_client bob(&fixture.bob);
  ASSERT_TRUE(bob.connect(fixture.port()));
  ASSERT_TRUE(bob.send_forward(kToken, "1-3"));
  ASSERT_TRUE(is_ready(bob.read_line()));

  fixture.service->revoke("someone-else");
  std::this_thread::sleep_for(200ms);
  EXPECT_EQ(fixture.driver.detaches(), 0u) << "revoking an unrelated client cut a forward";

  const auto started = std::chrono::steady_clock::now();
  fixture.service->revoke("alice-id");
  EXPECT_TRUE(detached_and_closed(fixture, alice));
  EXPECT_LT(std::chrono::steady_clock::now() - started, 2s);

  // Bob is untouched.
  auto kernel = fixture.driver.take_kernel("1-3");
  ASSERT_NE(kernel, nullptr);
  set_timeouts(*kernel, 2000);
  ASSERT_TRUE(bob.send("BOB"));
  char received[3] = {};
  boost::system::error_code ec;
  asio::read(*kernel, asio::buffer(received, 3), ec);
  EXPECT_FALSE(ec);
}

// ---- TLS hardening ---------------------------------------------------------------------------------------------

TEST(RemoteUsbTunnel, ATlsSessionIsNeverResumed) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());

  SSL_SESSION *session = nullptr;
  {
    tunnel_client first(&fixture.alice);
    ASSERT_TRUE(first.connect(fixture.port()));
    ASSERT_TRUE(first.send_forward(kWrongToken, "1-2"));
    ASSERT_TRUE(first.read_line().has_value());  // reading lets any session ticket arrive
    session = SSL_get1_session(first.stream->native_handle());
    // Close cleanly: OpenSSL marks the session of an unclean close as not resumable, which would make this
    // probe pass for the wrong reason (a client that cannot offer the session at all).
    boost::system::error_code ignored;
    first.stream->shutdown(ignored);
  }
  ASSERT_NE(session, nullptr);

  tunnel_client second(&fixture.alice);
  ASSERT_TRUE(second.connect(fixture.port(), 3000, session)) << "a client offering a session must still be able to connect";
  EXPECT_EQ(SSL_session_reused(second.stream->native_handle()), 0) << "the host resumed a session instead of verifying the certificate again";
  ASSERT_TRUE(second.send_forward(kToken, "1-2"));
  EXPECT_TRUE(is_ready(second.read_line()));
  SSL_SESSION_free(session);
}

// ---- restart, per-client slots, quiet logs -----------------------------------------------------------------------

TEST(RemoteUsbTunnel, TheServiceCanBeStartedAgainAfterItWasStopped) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  EXPECT_TRUE(is_ready(fixture.forward(&fixture.alice, kToken, "1-2")));
  ASSERT_TRUE(fixture.driver.wait_for_call(fake_driver::is_attach));
  fixture.service->stop();
  ASSERT_FALSE(fixture.service->running());

  ASSERT_TRUE(fixture.service->start(fixture.tunnel_config())) << "start after stop failed";
  EXPECT_TRUE(fixture.service->running());
  EXPECT_TRUE(is_ready(fixture.forward(&fixture.alice, kToken, "1-2"))) << "the restarted service did not forward";
  EXPECT_EQ(fixture.driver.attaches(), 2u) << "the second attach never reached the driver";
}

TEST(RemoteUsbTunnel, TwoClientsMayForwardTheirOwnDeviceWithTheSameBusId) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  tunnel_client first(&fixture.alice);
  ASSERT_TRUE(first.connect(fixture.port()));
  ASSERT_TRUE(first.send_forward(kToken, "1-2"));
  ASSERT_TRUE(is_ready(first.read_line()));
  tunnel_client second(&fixture.bob);
  ASSERT_TRUE(second.connect(fixture.port()));
  ASSERT_TRUE(second.send_forward(kToken, "1-2"));
  EXPECT_TRUE(is_ready(second.read_line())) << "one client's bus id number blocked another client's different device";
  EXPECT_EQ(fixture.driver.attaches(), 2u);
}

TEST(RemoteUsbTunnel, AScannersFailedTlsHandshakeIsLoggedQuietly) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  {
    asio::io_context io;
    tcp::socket scanner(io);
    boost::system::error_code ec;
    scanner.connect(tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), fixture.port()), ec);
    ASSERT_FALSE(ec);
    asio::write(scanner, asio::buffer(std::string("GET / HTTP/1.1\r\nHost: x\r\n\r\n")), ec);
    EXPECT_TRUE(closed_within(scanner, 3000));
  }
  const auto log = read_log_file();
  EXPECT_NE(log.find("Debug: Remote USB tunnel TLS rejected"), std::string::npos) << "the probe saw no rejection at all";
  EXPECT_EQ(log.find("Info: Remote USB tunnel TLS rejected"), std::string::npos);
  EXPECT_EQ(log.find("Warning: Remote USB tunnel TLS rejected"), std::string::npos);
}

// ---- revoking a client for real ---------------------------------------------------------------------------------

namespace {
  /** Leaves the process-wide deny list empty, whatever a test did. */
  struct tunnel_deny_guard {
    ~tunnel_deny_guard() {
      for (const auto &uuid : nvhttp::usb_forwarding_denied_clients()) {
        nvhttp::usb_forwarding_allow_client(uuid);
      }
    }
  };
}  // namespace

TEST(RemoteUsbTunnel, ARevokedClientCannotComeBackOthersAreUnaffectedAndClearingItRestoresAccess) {
  tunnel_deny_guard guard;
  tunnel_fixture fixture;
  // The recheck is an hour away, so only the revoke itself can end the forward.
  ASSERT_TRUE(fixture.start([](auto &config) { config.recheck_interval = std::chrono::hours(1); }));
  tunnel_client alice(&fixture.alice);
  establish(fixture, alice);

  // What the control pipe does: deny first, then cut.
  ASSERT_EQ(nvhttp::usb_forwarding_deny_client("alice-id"), nvhttp::usb_deny_result::added);
  fixture.service->revoke("alice-id");
  EXPECT_TRUE(detached_and_closed(fixture, alice));

  // She still holds the permission and the token, yet cannot attach again.
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kToken, "1-4")), "forbidden");
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kToken, "1-5")), "forbidden") << "a second try got in";
  // Bob is untouched.
  EXPECT_TRUE(is_ready(fixture.forward(&fixture.bob, kToken, "1-3")));

  ASSERT_TRUE(nvhttp::usb_forwarding_allow_client("alice-id"));
  EXPECT_TRUE(is_ready(fixture.forward(&fixture.alice, kToken, "1-4"))) << "clearing the revoke did not give access back";
}

TEST(RemoteUsbTunnel, DenyingAClientAloneEndsItsForwardAtTheNextRecheck) {
  tunnel_deny_guard guard;
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());  // rechecks every 150 ms
  tunnel_client alice(&fixture.alice);
  establish(fixture, alice);
  nvhttp::usb_forwarding_deny_client("alice-id");
  EXPECT_TRUE(detached_and_closed(fixture, alice));
}

TEST(RemoteUsbTunnel, ADenyOutlivesATokenRotation) {
  tunnel_deny_guard guard;
  tunnel_fixture fixture;
  nvhttp::usb_forwarding_deny_client("alice-id");
  nvhttp::usb_forwarding_rotate_token();
  const auto fresh = nvhttp::usb_forwarding_token();
  ASSERT_TRUE(fixture.start([&](auto &config) { config.session_token = fresh; }));
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, fresh, "1-2")), "forbidden");
  EXPECT_TRUE(is_ready(fixture.forward(&fixture.bob, fresh, "1-3")));
}

TEST(RemoteUsbTunnel, AfterARestartWithANewTokenTheOldTokenIsRefused) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start());
  EXPECT_TRUE(is_ready(fixture.forward(&fixture.alice, kToken, "1-2")));
  fixture.service->stop();

  auto config = fixture.tunnel_config();
  config.session_token = kWrongToken;  // what a restart through nvhttp does: a new random token
  ASSERT_TRUE(fixture.service->start(std::move(config)));
  EXPECT_EQ(error_reason(fixture.forward(&fixture.alice, kToken, "1-2")), "unauthorized") << "the token from before the restart still works";
  EXPECT_TRUE(is_ready(fixture.forward(&fixture.alice, kWrongToken, "1-2")));
}

TEST(RemoteUsbTunnel, TheServiceListsItsRunningForwardsAndCountsWhatARevokeCuts) {
  tunnel_fixture fixture;
  ASSERT_TRUE(fixture.start([](auto &config) { config.recheck_interval = std::chrono::hours(1); }));
  EXPECT_TRUE(fixture.service->forwards().value().empty());
  tunnel_client alice(&fixture.alice);
  establish(fixture, alice);
  tunnel_client bob(&fixture.bob);
  ASSERT_TRUE(bob.connect(fixture.port()));
  ASSERT_TRUE(bob.send_forward(kToken, "1-3"));
  ASSERT_TRUE(is_ready(bob.read_line()));

  auto forwards = fixture.service->forwards().value();
  ASSERT_EQ(forwards.size(), 2u);
  std::sort(forwards.begin(), forwards.end(), [](const auto &a, const auto &b) { return a.client_id < b.client_id; });
  EXPECT_EQ(forwards[0].client_id, "alice-id");
  EXPECT_EQ(forwards[0].busid, "1-2");
  EXPECT_EQ(forwards[1].client_id, "bob-id");
  EXPECT_EQ(forwards[1].busid, "1-3");
  EXPECT_GT(forwards[0].since_unix, 1700000000);

  EXPECT_EQ(fixture.service->revoke_counted("nobody"), std::optional<std::size_t> {0});
  EXPECT_EQ(fixture.service->revoke_counted("alice-id"), std::optional<std::size_t> {1});
  EXPECT_TRUE(detached_and_closed(fixture, alice));
}

#endif  // _WIN32
