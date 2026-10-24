/**
 * @file src/remote_usb/reverse_tunnel_service.h
 * @brief Reverse USB/IP tunnel endpoint for paired Moonlight clients.
 *
 * Derived from AlkaidLab/foundation-sunshine (GPL-3.0).
 *
 * The Moonlight client connects a platform USB/IP server (usbipd-win)
 * through a client-initiated TLS tunnel.  This service terminates that tunnel:
 * after a one-line JSON handshake it attaches usbip-win2 to an ephemeral
 * loopback port and pumps opaque bytes in both directions.  No USB/IP parsing
 * happens here: the protocol belongs to the USB/IP server and client at the two
 * ends of the tunnel.
 *
 * Wire contract (shared with the MoonlightVibe client):
 *   C -> S: {"op":"forward","token":"<session-token>","busid":"1-2"}\n
 *   S -> C: {"op":"ready"}\n                                  (then raw bytes)
 *   S -> C: {"op":"error","reason":"..."}\n                   (then close)
 *
 * A token alone is never enough.  The TLS layer demands a client certificate
 * that the injected verifier accepts, and after the token the injected
 * authorizer decides, for that same certificate, whether the client may
 * forward a device right now.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <openssl/ssl.h>

#include "client_authorization.h"
#include "forward_info.h"
#include "remote_usb_host_controller.h"

namespace remote_usb {

  /**
   * Finds the process that owns the connecting end of a loopback connection.
   * @param peer_port     the port the connecting socket is bound to (the remote port of the accepted socket)
   * @param listener_port the port of the listener it connected to
   * @return the owning process id, or nothing when it cannot be found (the connection is then refused)
   */
  using peer_pid_lookup = std::function<std::optional<std::uint32_t>(std::uint16_t peer_port, std::uint16_t listener_port)>;

  /** The system-wide lookup used in production (GetExtendedTcpTable); nothing on other platforms. */
  std::optional<std::uint32_t>
  tcp_loopback_peer_pid(std::uint16_t peer_port, std::uint16_t listener_port);

  struct reverse_tunnel_config {
    std::string bind_address { "0.0.0.0" };
    std::uint16_t port { 0 };
    /** Sessions that passed the token and the authorizer (forwards being set up or running). */
    std::size_t max_sessions { 16 };
    /** Connections that have not yet been authorized (TLS in progress, or no handshake line yet).
     *  Kept apart from max_sessions so scanners cannot crowd out working forwards. */
    std::size_t max_unauthenticated { 16 };
    /** Unauthorized connections allowed from one source address at a time. */
    std::size_t max_unauthenticated_per_address { 4 };
    /** How long a connection may take to finish the TLS handshake. */
    std::chrono::milliseconds tls_timeout { std::chrono::seconds(3) };
    /** How often every running forward is authorized again, so an unpaired client, a removed
     *  permission or an ended stream cuts the device off. */
    std::chrono::milliseconds recheck_interval { std::chrono::seconds(5) };
    std::string certificate_file;
    std::string private_key_file;
    /** Shared secret presented by the client in the JSON handshake. */
    std::string session_token;
    /** Decides whether a presented TLS client certificate is a paired
     *  Moonlight client; injected by the caller so this module never
     *  depends on the HTTP layer's pairing state. */
    std::function<bool(X509 *)> verify_client_cert;
    /** Called after the token matched, and again on every recheck, with the certificate the TLS
     *  layer accepted.  Required: a service without it refuses to start. */
    std::function<authorization_result(X509 *)> authorize_client;
    /** Covers the JSON handshake and the usbip-win2 attach once TLS is done, and bounds
     *  how long the loopback listener waits for the driver. */
    std::chrono::milliseconds startup_timeout { std::chrono::seconds(12) };
    /** The only process allowed to connect to the loopback attach listener.
     *  usbip-win2 connects from the kernel (WSK), which Windows attributes to System (4).
     *  Limit, stated precisely: PID 4 means "some kernel-mode TCP client", not "usbip-win2".
     *  The check keeps ordinary user-mode processes from taking the stream. A kernel-mode
     *  component that connects first can make this attach fail (denial of service). Kernel code
     *  can already read anything on this host, so this is not a data-exposure step up. */
    std::uint32_t attach_peer_pid { 4 };
    /** Empty selects tcp_loopback_peer_pid. Injectable for tests. */
    peer_pid_lookup attach_peer_pid_lookup;
    /** Claims the forwarding slot for one busid (one tunnel per device);
     *  wired by the service itself. Returns false when already claimed. */
    std::function<bool(const std::string &)> acquire_device_slot;
    /** Wired by the service itself: moves one session from "unauthorized" to "authorized"; false when full. */
    std::function<bool()> admit_authenticated;
    std::function<void(const std::string &)> release_device_slot;
  };

  /**
   * Owns the TLS listener, one tunnel per forwarded busid, and the
   * usbip-win2 attach/detach lifecycle.  All callbacks run on the service's
   * own io_context thread; stop() joins it.
   */
  class reverse_tunnel_service final {
  public:
    explicit reverse_tunnel_service(usbip_host_controller_config controller_config = {});
    ~reverse_tunnel_service();

    reverse_tunnel_service(const reverse_tunnel_service &) = delete;
    reverse_tunnel_service &
    operator=(const reverse_tunnel_service &) = delete;

    /**
     * Returns false (and logs one line) when the endpoint cannot be started.
     * The listener does not set SO_REUSEADDR, so a port another socket holds
     * is a failure, never a silent share.
     */
    bool
    start(reverse_tunnel_config config);

    void
    stop() noexcept;

    /** Detach and close every forward of this client at once; any thread. */
    void
    revoke(const std::string &client_id);

    /**
     * Like revoke(), but waits (at most @p timeout) for the service thread and returns how many
     * forwards it cut. Nothing when the service is not running or does not answer in time (the
     * revoke is then still carried out). Any thread except the service's own.
     */
    std::optional<std::size_t>
    revoke_counted(const std::string &client_id, std::chrono::milliseconds timeout = std::chrono::seconds(2));

    /**
     * The forwards that passed the token and the authorizer and have not ended. Waits at most
     * @p timeout for the service thread; nothing when it is not running or does not answer.
     * Any thread except the service's own.
     */
    std::optional<std::vector<forward_info>>
    forwards(std::chrono::milliseconds timeout = std::chrono::seconds(2)) const;

    /** True between a successful start() and stop(). */
    bool
    running() const noexcept;

    std::uint16_t
    bound_port() const noexcept;

  private:
    struct impl;
    std::shared_ptr<impl> impl_;
  };

}  // namespace remote_usb
