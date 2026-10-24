/**
 * @file src/remote_usb/usb_tunnel_manager.h
 * @brief Starts, stops and talks to the USB forwarding tunnel while Apollo runs.
 * @details Owns the one live tunnel instance and serialises every change of its state, so a
 *          start, a stop and a shutdown that arrive from different threads cannot interleave.
 *          The tunnel itself is behind a small interface so tests can use a fake.
 *
 * Locking. The lifecycle mutex serialises enable(), disable() and shutdown(); it is held while an
 * instance is started AND while it is stopped, which can take a while, so those three calls wait for
 * each other. The state mutex is only ever held to copy or swap the instance pointer, never across a
 * call into an instance, and always nests inside the lifecycle mutex. revoke(), revoke_counted(),
 * forwards(), running() and port() take only the state mutex, and call the instance after releasing
 * it, so they never wait for a slow start or stop. disable() and shutdown() remove the instance
 * from view before they stop it.
 */
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "forward_info.h"

namespace remote_usb {

  /** One running tunnel. */
  class tunnel_instance {
  public:
    virtual ~tunnel_instance() = default;

    virtual bool
    running() const = 0;

    virtual std::uint16_t
    port() const = 0;

    /** Detach everything and release the listener; may block; idempotent. */
    virtual void
    stop() noexcept = 0;

    /** Fire and forget: cut every forward of this client. Any thread. */
    virtual void
    revoke(const std::string &client_id) = 0;

    /** Cut every forward of this client and say how many; nothing when the instance cannot tell. */
    virtual std::optional<std::size_t>
    revoke_counted(const std::string &client_id) = 0;

    /** The forwards now running; nothing when the instance cannot tell. */
    virtual std::optional<std::vector<forward_info>>
    forwards() = 0;
  };

  /** Why a tunnel could not be started. Fixed codes, safe to put in a reply. */
  enum class start_failure : std::uint8_t {
    none,
    /** The port is out of range, or one this host uses itself. */
    port_refused,
    /** Anything else (port busy, certificate unreadable, ...). The reason is already logged. */
    failed,
  };

  enum class manager_result : std::uint8_t {
    ok,
    port_refused,
    start_failed,
    /** The process is going down; the tunnel will not be started again. */
    shutting_down,
  };

  class usb_tunnel_manager {
  public:
    /** Builds and starts a tunnel; null (with @p failure set) when it cannot. Called with the lifecycle lock held. */
    using starter = std::function<std::shared_ptr<tunnel_instance>(start_failure &failure)>;

    /** @param on_change called with the lifecycle lock held after every change: (enabled, running, port). */
    explicit usb_tunnel_manager(starter make_instance, std::function<void(bool, bool, std::uint16_t)> on_change = {});
    ~usb_tunnel_manager();

    usb_tunnel_manager(const usb_tunnel_manager &) = delete;
    usb_tunnel_manager &
    operator=(const usb_tunnel_manager &) = delete;

    /** Start the tunnel unless it already runs (then ok, and nothing changes). */
    manager_result
    enable();

    /** Stop the tunnel and detach everything unless it is already off. Refused only after shutdown. */
    manager_result
    disable();

    /** Final stop. After it enable() answers shutting_down. Safe from any thread, any number of times. */
    void
    shutdown() noexcept;

    /** The tunnel is on, as far as callers are concerned. */
    bool
    enabled() const noexcept {
      return enabled_.load();
    }

    bool
    running() const;

    std::uint16_t
    port() const;

    void
    revoke(const std::string &client_id);

    /** Cut every forward of this client; how many were cut (0 when the tunnel is off or did not answer). */
    std::size_t
    revoke_counted(const std::string &client_id);

    std::vector<forward_info>
    forwards();

  private:
    std::shared_ptr<tunnel_instance>
    current() const;

    starter make_instance_;
    std::function<void(bool, bool, std::uint16_t)> on_change_;

    std::mutex lifecycle_mutex_;
    mutable std::mutex state_mutex_;
    std::shared_ptr<tunnel_instance> instance_;
    std::atomic_bool enabled_ {false};
    std::atomic_bool shutdown_ {false};
  };

}  // namespace remote_usb
