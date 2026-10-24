/**
 * @file tests/unit/test_usb_tunnel_manager.cpp
 * @brief Behaviour tests for the tunnel lifecycle (src/remote_usb/usb_tunnel_manager.cpp).
 * @details The tunnel is a fake that counts how many instances are alive at once, so a start/stop race shows up
 *          as a number, not as a hunch. Nothing here opens a socket or touches usbip.
 */
#ifdef _WIN32

  #include <src/remote_usb/usb_tunnel_manager.h>

  #include <atomic>
  #include <chrono>
  #include <condition_variable>
  #include <functional>
  #include <memory>
  #include <optional>
  #include <mutex>
  #include <thread>
  #include <vector>

  #include <gtest/gtest.h>

namespace {

  using namespace std::chrono_literals;
  using remote_usb::forward_info;
  using remote_usb::manager_result;
  using remote_usb::start_failure;
  using remote_usb::tunnel_instance;
  using remote_usb::usb_tunnel_manager;

  /** Shared bookkeeping for every fake instance a test creates. */
  struct world {
    std::atomic<int> created {0};
    std::atomic<int> stopped {0};
    std::atomic<int> live {0};
    std::atomic<int> max_live {0};
    std::atomic<int> changes {0};
    std::atomic<bool> last_enabled {false};
    std::atomic<std::uint16_t> last_port {0};

    std::mutex gate_mutex;
    std::condition_variable gate_cv;
    bool hold_start {false};  // starter blocks until released
    bool hold_stop {false};   // stop() blocks until released
    std::atomic<int> in_start {0};
    std::atomic<int> in_stop {0};

    std::mutex revoke_mutex;
    std::vector<std::string> revoked;

    void
    wait_gate(bool world::*flag) {
      std::unique_lock lock {gate_mutex};
      gate_cv.wait(lock, [&] { return !(this->*flag); });
    }
    void
    set_gate(bool world::*flag, bool value) {
      {
        const std::lock_guard lock {gate_mutex};
        this->*flag = value;
      }
      gate_cv.notify_all();
    }
  };

  class fake_instance final: public tunnel_instance {
  public:
    explicit fake_instance(world &w):
        w_(w) {
      const int now = ++w_.live;
      int seen = w_.max_live.load();
      while (now > seen && !w_.max_live.compare_exchange_weak(seen, now)) {
      }
      ++w_.created;
    }

    bool
    running() const override {
      return !stopped_.load();
    }
    std::uint16_t
    port() const override {
      return 48100;
    }
    void
    stop() noexcept override {
      ++w_.in_stop;
      w_.wait_gate(&world::hold_stop);
      if (!stopped_.exchange(true)) {
        ++w_.stopped;
        --w_.live;
      }
      --w_.in_stop;
    }
    void
    revoke(const std::string &client_id) override {
      const std::lock_guard lock {w_.revoke_mutex};
      w_.revoked.push_back(client_id);
    }
    std::optional<std::size_t>
    revoke_counted(const std::string &client_id) override {
      if (client_id == "client-q") {
        return std::nullopt;  // cannot tell
      }
      revoke(client_id);
      return client_id == "client-a" ? 2 : 0;
    }
    std::optional<std::vector<forward_info>>
    forwards() override {
      return std::vector<forward_info> {{"client-a", "1-2", 100}, {"client-b", "1-3", 200}};
    }

  private:
    world &w_;
    std::atomic<bool> stopped_ {false};
  };

  std::unique_ptr<usb_tunnel_manager>
  make_manager(world &w, start_failure fail_with = start_failure::none) {
    return std::make_unique<usb_tunnel_manager>(
      [&w, fail_with](start_failure &failure) -> std::shared_ptr<tunnel_instance> {
        ++w.in_start;
        w.wait_gate(&world::hold_start);
        --w.in_start;
        if (fail_with != start_failure::none) {
          failure = fail_with;
          return nullptr;
        }
        return std::make_shared<fake_instance>(w);
      },
      [&w](bool enabled, bool, std::uint16_t port) {
        ++w.changes;
        w.last_enabled = enabled;
        w.last_port = port;
      });
  }

  bool
  wait_until(const std::function<bool()> &condition, std::chrono::milliseconds limit = 3s) {
    const auto end = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < end) {
      if (condition()) {
        return true;
      }
      std::this_thread::sleep_for(2ms);
    }
    return condition();
  }

}  // namespace

TEST(UsbTunnelManager, StartsOffAndNothingIsCreated) {
  world w;
  auto manager = make_manager(w);
  EXPECT_FALSE(manager->enabled());
  EXPECT_FALSE(manager->running());
  EXPECT_EQ(manager->port(), 0);
  EXPECT_TRUE(manager->forwards().empty());
  EXPECT_EQ(w.created.load(), 0);
}

TEST(UsbTunnelManager, StartStopStartLiveGivesTwoSeparateInstances) {
  world w;
  auto manager = make_manager(w);

  ASSERT_EQ(manager->enable(), manager_result::ok);
  EXPECT_TRUE(manager->enabled());
  EXPECT_TRUE(manager->running());
  EXPECT_EQ(manager->port(), 48100);
  EXPECT_TRUE(w.last_enabled.load());

  ASSERT_EQ(manager->disable(), manager_result::ok);
  EXPECT_FALSE(manager->enabled());
  EXPECT_FALSE(manager->running());
  EXPECT_EQ(manager->port(), 0);
  EXPECT_EQ(w.stopped.load(), 1);
  EXPECT_EQ(w.live.load(), 0);

  ASSERT_EQ(manager->enable(), manager_result::ok);
  EXPECT_TRUE(manager->running());
  EXPECT_EQ(w.created.load(), 2);
  EXPECT_EQ(w.live.load(), 1);
}

TEST(UsbTunnelManager, EnableAndDisableAreIdempotent) {
  world w;
  auto manager = make_manager(w);
  ASSERT_EQ(manager->enable(), manager_result::ok);
  ASSERT_EQ(manager->enable(), manager_result::ok);
  EXPECT_EQ(w.created.load(), 1);
  ASSERT_EQ(manager->disable(), manager_result::ok);
  ASSERT_EQ(manager->disable(), manager_result::ok);
  EXPECT_EQ(w.stopped.load(), 1);
}

TEST(UsbTunnelManager, AFailedStartLeavesItOffAndSaysWhy) {
  {
    world w;
    auto manager = make_manager(w, start_failure::port_refused);
    EXPECT_EQ(manager->enable(), manager_result::port_refused);
    EXPECT_FALSE(manager->enabled());
    EXPECT_FALSE(manager->running());
    EXPECT_EQ(w.changes.load(), 0);
  }
  {
    world w;
    auto manager = make_manager(w, start_failure::failed);
    EXPECT_EQ(manager->enable(), manager_result::start_failed);
    EXPECT_FALSE(manager->enabled());
  }
}

TEST(UsbTunnelManager, ConcurrentEnableCallsStartExactlyOneInstance) {
  world w;
  auto manager = make_manager(w);
  std::vector<std::thread> threads;
  std::atomic<int> ok {0};
  for (int i = 0; i < 12; ++i) {
    threads.emplace_back([&] {
      if (manager->enable() == manager_result::ok) {
        ++ok;
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }
  EXPECT_EQ(ok.load(), 12);
  EXPECT_EQ(w.created.load(), 1);
  EXPECT_EQ(w.max_live.load(), 1);
}

TEST(UsbTunnelManager, ConcurrentEnableAndDisableNeverRunTwoTunnelsAtOnce) {
  world w;
  auto manager = make_manager(w);
  std::vector<std::thread> threads;
  for (int t = 0; t < 6; ++t) {
    threads.emplace_back([&, t] {
      for (int i = 0; i < 200; ++i) {
        if ((i + t) % 2 == 0) {
          manager->enable();
        }
        else {
          manager->disable();
        }
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }
  EXPECT_EQ(w.max_live.load(), 1) << "two tunnels were alive at the same time";
  EXPECT_EQ(w.live.load(), manager->running() ? 1 : 0);
  manager->disable();
  EXPECT_EQ(w.live.load(), 0);
  EXPECT_EQ(w.created.load(), w.stopped.load());
}

TEST(UsbTunnelManager, ShutdownIsFinalAndEnableAfterwardsIsRefused) {
  world w;
  auto manager = make_manager(w);
  ASSERT_EQ(manager->enable(), manager_result::ok);
  manager->shutdown();
  EXPECT_EQ(w.live.load(), 0);
  EXPECT_FALSE(manager->enabled());
  EXPECT_EQ(manager->enable(), manager_result::shutting_down);
  EXPECT_EQ(manager->disable(), manager_result::shutting_down);
  EXPECT_EQ(w.created.load(), 1) << "enable after shutdown must not build a tunnel";
  manager->shutdown();  // again: harmless
  EXPECT_EQ(w.stopped.load(), 1);
}

TEST(UsbTunnelManager, ShutdownDuringAnEnableLeavesNothingRunning) {
  world w;
  auto manager = make_manager(w);
  w.set_gate(&world::hold_start, true);

  std::atomic<manager_result> enable_result {manager_result::start_failed};
  std::thread enabler([&] { enable_result = manager->enable(); });
  ASSERT_TRUE(wait_until([&] { return w.in_start.load() == 1; }));

  std::thread closer([&] { manager->shutdown(); });
  std::this_thread::sleep_for(50ms);  // the shutdown is now queued behind the start
  w.set_gate(&world::hold_start, false);
  enabler.join();
  closer.join();

  EXPECT_EQ(w.live.load(), 0) << "a tunnel survived the shutdown";
  EXPECT_FALSE(manager->running());
  EXPECT_EQ(manager->enable(), manager_result::shutting_down);
}

TEST(UsbTunnelManager, AnEnableQueuedBehindAShutdownIsRefused) {
  world w;
  auto manager = make_manager(w);
  ASSERT_EQ(manager->enable(), manager_result::ok);
  w.set_gate(&world::hold_stop, true);

  std::thread closer([&] { manager->shutdown(); });
  ASSERT_TRUE(wait_until([&] { return w.in_stop.load() == 1; }));

  std::atomic<manager_result> result {manager_result::ok};
  std::thread enabler([&] { result = manager->enable(); });
  std::this_thread::sleep_for(50ms);
  w.set_gate(&world::hold_stop, false);
  closer.join();
  enabler.join();

  EXPECT_EQ(result.load(), manager_result::shutting_down);
  EXPECT_EQ(w.created.load(), 1);
  EXPECT_EQ(w.live.load(), 0);
}

TEST(UsbTunnelManager, RevokeOnlyReachesTheNamedClientAndCountsIt) {
  world w;
  auto manager = make_manager(w);
  ASSERT_EQ(manager->enable(), manager_result::ok);

  EXPECT_EQ(manager->revoke_counted("client-a"), std::size_t {2});
  EXPECT_EQ(manager->revoke_counted("client-z"), std::size_t {0});
  manager->revoke("client-b");
  const std::lock_guard lock {w.revoke_mutex};
  ASSERT_EQ(w.revoked.size(), 3u);
  EXPECT_EQ(w.revoked[0], "client-a");
  EXPECT_EQ(w.revoked[1], "client-z");
  EXPECT_EQ(w.revoked[2], "client-b");
}

TEST(UsbTunnelManager, AnInstanceThatCannotCountCountsAsZeroNotAsAnError) {
  world w;
  auto manager = make_manager(w);
  ASSERT_EQ(manager->enable(), manager_result::ok);
  EXPECT_EQ(manager->revoke_counted("client-q"), std::size_t {0});
}

TEST(UsbTunnelManager, RevokeWhileOffIsHarmless) {
  world w;
  auto manager = make_manager(w);
  manager->revoke("client-a");
  EXPECT_EQ(manager->revoke_counted("client-a"), std::size_t {0});
  EXPECT_TRUE(w.revoked.empty());
}

TEST(UsbTunnelManager, ForwardsComeFromTheRunningTunnel) {
  world w;
  auto manager = make_manager(w);
  ASSERT_EQ(manager->enable(), manager_result::ok);
  const auto forwards = manager->forwards();
  ASSERT_EQ(forwards.size(), 2u);
  EXPECT_EQ(forwards[0].client_id, "client-a");
  EXPECT_EQ(forwards[0].busid, "1-2");
  EXPECT_EQ(forwards[1].since_unix, 200);
}

TEST(UsbTunnelManager, RevokeIsNotHeldUpByATunnelThatIsStillStopping) {
  world w;
  auto manager = make_manager(w);
  ASSERT_EQ(manager->enable(), manager_result::ok);
  w.set_gate(&world::hold_stop, true);

  std::thread disabler([&] { manager->disable(); });
  ASSERT_TRUE(wait_until([&] { return w.in_stop.load() == 1; }));

  // The unpair and permission hooks of the HTTPS server call this; they must never wait for a slow stop.
  std::atomic<bool> returned {false};
  std::thread revoker([&] {
    manager->revoke("client-a");
    (void) manager->revoke_counted("client-a");
    (void) manager->forwards();
    returned = true;
  });
  EXPECT_TRUE(wait_until([&] { return returned.load(); }, 1s)) << "revoke blocked behind stop()";

  w.set_gate(&world::hold_stop, false);
  disabler.join();
  revoker.join();
}

#endif  // _WIN32
