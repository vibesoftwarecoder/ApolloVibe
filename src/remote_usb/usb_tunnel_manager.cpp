/**
 * @file src/remote_usb/usb_tunnel_manager.cpp
 */
#include "src/remote_usb/usb_tunnel_manager.h"

#include <utility>

namespace remote_usb {

  usb_tunnel_manager::usb_tunnel_manager(starter make_instance, std::function<void(bool, bool, std::uint16_t)> on_change):
      make_instance_(std::move(make_instance)),
      on_change_(std::move(on_change)) {}

  usb_tunnel_manager::~usb_tunnel_manager() {
    shutdown();
  }

  std::shared_ptr<tunnel_instance>
  usb_tunnel_manager::current() const {
    const std::lock_guard lock {state_mutex_};
    return instance_;
  }

  manager_result
  usb_tunnel_manager::enable() {
    const std::lock_guard lifecycle {lifecycle_mutex_};
    // Checked after the lock: a shutdown that was waiting for us has already set the flag.
    if (shutdown_.load()) {
      return manager_result::shutting_down;
    }
    if (current()) {
      return manager_result::ok;
    }

    start_failure failure = start_failure::none;
    auto instance = make_instance_ ? make_instance_(failure) : nullptr;
    if (!instance) {
      return failure == start_failure::port_refused ? manager_result::port_refused : manager_result::start_failed;
    }

    const auto port = instance->port();
    {
      const std::lock_guard lock {state_mutex_};
      instance_ = instance;
    }
    enabled_ = true;
    if (on_change_) {
      on_change_(true, true, port);
    }
    return manager_result::ok;
  }

  manager_result
  usb_tunnel_manager::disable() {
    const std::lock_guard lifecycle {lifecycle_mutex_};
    if (shutdown_.load()) {
      return manager_result::shutting_down;
    }
    std::shared_ptr<tunnel_instance> instance;
    {
      const std::lock_guard lock {state_mutex_};
      instance = std::move(instance_);
    }
    enabled_ = false;
    if (on_change_) {
      on_change_(false, false, 0);
    }
    // Stop after the instance is unreachable, so nobody starts a call on a tunnel that is going away.
    if (instance) {
      instance->stop();
    }
    return manager_result::ok;
  }

  void
  usb_tunnel_manager::shutdown() noexcept {
    // Set first and without the lock: an enable() queued behind us must see it.
    shutdown_ = true;
    try {
      const std::lock_guard lifecycle {lifecycle_mutex_};
      std::shared_ptr<tunnel_instance> instance;
      {
        const std::lock_guard lock {state_mutex_};
        instance = std::move(instance_);
      }
      enabled_ = false;
      if (on_change_) {
        on_change_(false, false, 0);
      }
      if (instance) {
        instance->stop();
      }
    }
    catch (...) {
      // noexcept by contract: a mutex failure here leaves nothing more to do.
    }
  }

  bool
  usb_tunnel_manager::running() const {
    const auto instance = current();
    return instance && instance->running();
  }

  std::uint16_t
  usb_tunnel_manager::port() const {
    const auto instance = current();
    return instance ? instance->port() : 0;
  }

  void
  usb_tunnel_manager::revoke(const std::string &client_id) {
    if (const auto instance = current()) {
      instance->revoke(client_id);
    }
  }

  std::size_t
  usb_tunnel_manager::revoke_counted(const std::string &client_id) {
    if (const auto instance = current()) {
      // An instance that cannot tell (it is stopping, or did not answer in time) has still been told to cut.
      return instance->revoke_counted(client_id).value_or(0);
    }
    return 0;
  }

  std::vector<forward_info>
  usb_tunnel_manager::forwards() {
    if (const auto instance = current()) {
      return instance->forwards().value_or(std::vector<forward_info> {});
    }
    return {};
  }

}  // namespace remote_usb
