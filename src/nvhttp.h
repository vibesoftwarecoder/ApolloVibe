/**
 * @file src/nvhttp.h
 * @brief Declarations for the nvhttp (GameStream) server.
 */
// macros
#pragma once

// standard includes
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <chrono>
#include <list>
#include <memory>

// lib includes
#include <boost/property_tree/ptree.hpp>
#include <nlohmann/json.hpp>
#include <Simple-Web-Server/server_https.hpp>

// local includes
#include "crypto.h"
#include "remote_usb/client_authorization.h"
#ifdef _WIN32
  #include "remote_usb/usb_control_pipe.h"
  #include "remote_usb/reverse_tunnel_service.h"
  #include "remote_usb/usb_tunnel_manager.h"
#endif
#include "rtsp.h"
#include "thread_safe.h"

using namespace std::chrono_literals;

/**
 * @brief Contains all the functions and variables related to the nvhttp (GameStream) server.
 */
namespace nvhttp {

  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  using cmd_list_t = std::list<crypto::command_entry_t>;

  /**
   * @brief The protocol version.
   * @details The version of the GameStream protocol we are mocking.
   * @note The negative 4th number indicates to Moonlight that this is Sunshine.
   */
  constexpr auto VERSION = "7.1.431.-1";

  /**
   * @brief The GFE version we are replicating.
   */
  constexpr auto GFE_VERSION = "3.23.0.74";

  /**
   * @brief The HTTP port, as a difference from the config port.
   */
  constexpr auto PORT_HTTP = 0;

  /**
   * @brief The HTTPS port, as a difference from the config port.
   */
  constexpr auto PORT_HTTPS = -5;

  /**
   * @brief The USB forwarding tunnel port, as a difference from the config port, when `usb_forwarding_port` is 0.
   */
  constexpr auto USB_FORWARDING_PORT_OFFSET = 7;

  constexpr auto OTP_EXPIRE_DURATION = 180s;

  /**
   * @brief Start the nvhttp server.
   * @examples
   * nvhttp::start();
   * @examples_end
   */
  void start();

  std::string
  get_arg(const args_t &args, const char *name, const char *default_value = nullptr);

  // Helper function to extract command entries
  cmd_list_t
  extract_command_entries(const nlohmann::json& j, const std::string& key);

  std::shared_ptr<rtsp_stream::launch_session_t>
  make_launch_session(bool host_audio, bool input_only, const args_t &args, const crypto::named_cert_t* named_cert_p);

  /**
   * @brief Setup the nvhttp server.
   * @param pkey
   * @param cert
   */
  void setup(const std::string &pkey, const std::string &cert);

  class SunshineHTTPS: public SimpleWeb::HTTPS {
  public:
    SunshineHTTPS(boost::asio::io_context &io_context, boost::asio::ssl::context &ctx):
        SimpleWeb::HTTPS(io_context, ctx) {
    }

    virtual ~SunshineHTTPS() {
      // Gracefully shutdown the TLS connection
      SimpleWeb::error_code ec;
      shutdown(ec);
    }
  };

  enum class PAIR_PHASE {
    NONE,  ///< Sunshine is not in a pairing phase
    GETSERVERCERT,  ///< Sunshine is in the get server certificate phase
    CLIENTCHALLENGE,  ///< Sunshine is in the client challenge phase
    SERVERCHALLENGERESP,  ///< Sunshine is in the server challenge response phase
    CLIENTPAIRINGSECRET  ///< Sunshine is in the client pairing secret phase
  };

  struct pair_session_t {
    struct {
      std::string uniqueID = {};
      std::string cert = {};
      std::string name = {};
    } client;

    std::unique_ptr<crypto::aes_t> cipher_key = {};
    std::vector<uint8_t> clienthash = {};

    std::string serversecret = {};
    std::string serverchallenge = {};

    struct {
      util::Either<
        std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Response>,
        std::shared_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Response>>
        response;
      std::string salt = {};
    } async_insert_pin;

    /**
     * @brief used as a security measure to prevent out of order calls
     */
    PAIR_PHASE last_phase = PAIR_PHASE::NONE;
  };

  /**
   * @brief removes the temporary pairing session
   * @param sess
   */
  void remove_session(const pair_session_t &sess);

  /**
   * @brief Pair, phase 1
   *
   * Moonlight will send a salt and client certificate, we'll also need the user provided pin.
   *
   * PIN and SALT will be used to derive a shared AES key that needs to be stored
   * in order to be used to decrypt_symmetric in the next phases.
   *
   * At this stage we only have to send back our public certificate.
   */
  void getservercert(pair_session_t &sess, boost::property_tree::ptree &tree, const std::string &pin);

  /**
   * @brief Pair, phase 2
   *
   * Using the AES key that we generated in phase 1 we have to decrypt the client challenge,
   *
   * We generate a SHA256 hash with the following:
   *  - Decrypted challenge
   *  - Server certificate signature
   *  - Server secret: a randomly generated secret
   *
   * The hash + server_challenge will then be AES encrypted and sent as the `challengeresponse` in the returned XML
   */
  void clientchallenge(pair_session_t &sess, boost::property_tree::ptree &tree, const std::string &challenge);

  /**
   * @brief Pair, phase 3
   *
   * Moonlight will send back a `serverchallengeresp`: an AES encrypted client hash,
   * we have to send back the `pairingsecret`:
   * using our private key we have to sign the certificate_signature + server_secret (generated in phase 2)
   */
  void serverchallengeresp(pair_session_t &sess, boost::property_tree::ptree &tree, const std::string &encrypted_response);

  /**
   * @brief Pair, phase 4 (final)
   *
   * We now have to use everything we exchanged before in order to verify and finally pair the clients
   *
   * We'll check the client_hash obtained at phase 3, it should contain the following:
   *   - The original server_challenge
   *   - The signature of the X509 client_cert
   *   - The unencrypted client_pairing_secret
   * We'll check that SHA256(server_challenge + client_public_cert_signature + client_secret) == client_hash
   *
   * Then using the client certificate public key we should be able to verify that
   * the client secret has been signed by Moonlight
   */
  void clientpairingsecret(pair_session_t &sess, boost::property_tree::ptree &tree, const std::string &client_pairing_secret);

  /**
   * @brief Compare the user supplied pin to the Moonlight pin.
   * @param pin The user supplied pin.
   * @param name The user supplied name.
   * @return `true` if the pin is correct, `false` otherwise.
   * @examples
   * bool pin_status = nvhttp::pin("1234", "laptop");
   * @examples_end
   */
  bool pin(std::string pin, std::string name);

  std::string request_otp(const std::string& passphrase, const std::string& deviceName);

  /**
   * @brief Remove single client.
   * @param uuid The UUID of the client to remove.
   * @examples
   * nvhttp::unpair_client("4D7BB2DD-5704-A405-B41C-891A022932E1");
   * @examples_end
   */
  bool unpair_client(std::string_view uuid);

  /**
   * @brief Get all paired clients.
   * @return The list of all paired clients.
   * @examples
   * nlohmann::json clients = nvhttp::get_all_clients();
   * @examples_end
   */
  nlohmann::json get_all_clients();

  /**
   * @brief Remove all paired clients.
   * @examples
   * nvhttp::erase_all_clients();
   * @examples_end
   */
  void erase_all_clients();

  /**
   * @brief      Stops a session.
   *
   * @param      session   The session
   * @param[in]  graceful  Whether to stop gracefully
   */
  void stop_session(stream::session_t& session, bool graceful);

  /**
   * @brief      Finds and stop session.
   *
   * @param[in]  uuid      The uuid string
   * @param[in]  graceful  Whether to stop gracefully
   */
  bool find_and_stop_session(const std::string& uuid, bool graceful);

  /**
   * @brief      Update device info associated to the session
   *
   * @param      session  The session
   * @param[in]  name     New name
   * @param[in]  newPerm  New permission
   */
  void update_session_info(stream::session_t& session, const std::string& name, const crypto::PERM newPerm);

  /**
   * @brief      Finds and udpate session information.
   *
   * @param[in]  uuid     The uuid string
   * @param[in]  name     New name
   * @param[in]  newPerm  New permission
   */
  bool find_and_udpate_session_info(const std::string& uuid, const std::string& name, const crypto::PERM newPerm);

  /**
   * @brief      Update device info
   *
   * @param[in]  uuid       The uuid string
   * @param[in]  name       New name
   * @param[in]  do_cmds    The do commands
   * @param[in]  undo_cmds  The undo commands
   * @param[in]  newPerm    New permission
   * @param[in]  enable_legacy_ordering  Enable legacy ordering
   * @param[in]  allow_client_commands  Allow client commands
   * @param[in]  always_use_virtual_display  Always use virtual display
   * 
   * @return     Whether the update is successful
   */
  bool update_device_info(
    const std::string& uuid,
    const std::string& name,
    const std::string& display_mode,
    const cmd_list_t& do_cmds,
    const cmd_list_t& undo_cmds,
    const crypto::PERM newPerm,
    const bool enable_legacy_ordering,
    const bool allow_client_commands,
    const bool always_use_virtual_display
  );

  /**
   * @brief What one client is told about USB forwarding. Maps one-to-one to the `reason` field.
   */
  enum class usb_forwarding_state {
    disabled,     ///< The host owner has not turned USB forwarding on.
    unavailable,  ///< On, but this client cannot use it right now (no tunnel service, or no active stream).
    forbidden,    ///< On, but this client lacks PERM::usb_forward.
    ready,        ///< The client may open the tunnel.
  };

  /**
   * @brief Everything the capability decision depends on.
   */
  struct usb_forwarding_inputs {
    bool enabled {false};            ///< config::nvhttp.usb_forwarding_enabled
    bool service_running {false};    ///< The tunnel listener is up.
    crypto::PERM perm {crypto::PERM::_no};  ///< Permissions of the calling client.
    bool require_stream {true};      ///< config::nvhttp.usb_forwarding_require_stream
    bool has_active_stream {false};  ///< The calling client has a launch/stream session now.
    bool denied {false};             ///< The host owner refused this client until Apollo restarts (see usb_forwarding_deny_client).
  };

  /**
   * @brief Whether a client that presented a valid certificate may use the tunnel right now.
   * @details Shared by the capability reply and the tunnel handshake so the two cannot disagree.
   *          The order is: not enabled, no running service, client denied by the host owner, no permission, no stream.
   */
  usb_forwarding_state usb_forwarding_decide(const usb_forwarding_inputs &inputs);

  /**
   * @brief Build the body of the `GET /api/v1/usb-forwarding` capability reply (contract version 1).
   * @details `version`, `enabled`, `available` and `reason` are always present. `port` and `token` are present
   *          only for `usb_forwarding_state::ready`, so a host that is off, or a client that is not allowed,
   *          never receives credentials. A ready state with an unusable port or a token that is not 64 hex
   *          digits is reported as unavailable instead of being sent.
   * @param state The decision for this client.
   * @param port The tunnel port.
   * @param token The tunnel token, 64 hex digits.
   * @return The JSON body as a string.
   */
  std::string usb_forwarding_capability_json(usb_forwarding_state state, std::uint16_t port, std::string_view token);

  /**
   * @brief Pick the tunnel port.
   * @param configured `usb_forwarding_port`: 0 for the main port + 7, otherwise 1024-65535.
   * @param main_port The main (config) port that the other ports are offsets of.
   * @return The port, or nothing when it is out of range or collides with a port this host uses itself
   *         (offsets -5, 0, +1, +9..+12 and the RTSP port).
   */
  std::optional<std::uint16_t> usb_forwarding_resolve_port(int configured, std::uint16_t main_port);

  /**
   * @brief The tunnel's own decision about a client it has already authenticated by certificate.
   * @details Uses the same rules as the capability reply, with the service known to be running.
   * @param perm The permissions of the client that owns the certificate.
   * @param require_stream Whether `usb_forwarding_require_stream` is on.
   * @param has_active_stream Whether the client has a launch/stream session now.
   * @param client_uuid The paired client the certificate belongs to. Required: the deny list is looked up by it.
   */
  remote_usb::client_authorization usb_forwarding_client_authorization(crypto::PERM perm, bool require_stream, bool has_active_stream, const std::string &client_uuid);

  /**
   * @brief The inputs of the capability decision for one client; what the capability route uses.
   * @details Includes the runtime deny list, so a client that was revoked is told "forbidden" and gets no port or token.
   */
  usb_forwarding_inputs usb_forwarding_inputs_for_client(bool service_running, crypto::PERM perm, const std::string &client_uuid, bool has_active_stream);

  /** Most clients the runtime deny list holds. */
  constexpr std::size_t USB_FORWARDING_MAX_DENIED = 256;

  enum class usb_deny_result {
    added,
    already_denied,
    full,
  };

  /**
   * @brief Refuse this client USB forwarding until Apollo restarts or usb_forwarding_allow_client is called.
   * @details Uuids are compared case-insensitively (paired clients are stored in upper case, so that is the form kept).
   *          When the list is full, entries of clients that are no longer paired are dropped first.
   *          Memory only, bounded by USB_FORWARDING_MAX_DENIED. It does not unpair the client and does not
   *          change its stored permission. The tunnel handshake, its periodic recheck and the capability
   *          reply all consult it.
   */
  usb_deny_result usb_forwarding_deny_client(const std::string &uuid);

  /** Take a client off the deny list; true when it was on it. */
  bool usb_forwarding_allow_client(const std::string &uuid);

  bool usb_forwarding_client_denied(const std::string &uuid);

  std::vector<std::string> usb_forwarding_denied_clients();

  /**
   * @brief Cut every USB forward that belongs to this paired client (by uuid), at once.
   * @details Called when a client is unpaired or loses its permissions. Safe from any thread, a no-op when the
   *          tunnel is not running. The tunnel also authorizes every forward again on a timer, as a backstop.
   */
  void usb_forwarding_revoke_client(const std::string &uuid);

  /**
   * @brief The current tunnel token: 32 random bytes as 64 lower-case hex digits, created on first use.
   */
  std::string usb_forwarding_token();

  /**
   * @brief Replace the tunnel token with a new random one. Called each time the tunnel is started.
   */
  void usb_forwarding_rotate_token();

#ifdef _WIN32
  /**
   * @brief The object the USB control pipe talks to: status, live start/stop of the tunnel, revoking one client.
   * @details It reads and changes the same state as the HTTPS handlers and takes the same locks. Windows only.
   */
  std::unique_ptr<remote_usb::usb_control_backend> make_usb_control_backend();

  /**
   * @brief Start the control pipe when `usb_forwarding_control` is enabled; what nvhttp::start() calls.
   * @param backend The object the pipe talks to; must outlive the pipe.
   * @param base Settings for the pipe; an empty name selects the production name, which carries the main port.
   * @return The running pipe, or null when the key is off (nothing is created) or the pipe cannot be started.
   */
  std::unique_ptr<remote_usb::usb_control_pipe> start_usb_control(remote_usb::usb_control_backend &backend, remote_usb::usb_control_pipe_config base = {});

  /**
   * @brief Build the settings of a tunnel start: port check, credentials and a NEW token.
   * @param failure Set to port_refused when the configured port is out of range or collides with a port this host uses.
   * @return The settings, or nothing when the port is refused. Rotates the token each time it succeeds.
   */
  std::optional<remote_usb::reverse_tunnel_config> make_usb_tunnel_config(remote_usb::start_failure &failure);
#endif
}  // namespace nvhttp
