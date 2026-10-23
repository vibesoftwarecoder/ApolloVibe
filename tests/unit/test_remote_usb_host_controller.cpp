/**
 * @file tests/unit/test_remote_usb_host_controller.cpp
 * @brief Contract and lifecycle tests for the usbip-win2 process adapter.
 *
 * Derived from AlkaidLab/foundation-sunshine (GPL-3.0).
 */

#ifdef _WIN32

#include <src/remote_usb/remote_usb_host_controller.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace std::chrono_literals;

/* The production check would refuse these made-up paths; the tests that exercise it use their own. */
remote_usb::executable_check
accept_any_executable(const std::string &) {
  return { true, {} };
}

struct command_call {
  std::string executable;
  std::vector<std::string> arguments;
};

struct command_harness {
  std::mutex mutex;
  std::condition_variable condition;
  std::vector<command_call> calls;
  std::function<remote_usb::usbip_command_result(
    const std::vector<std::string> &,
    const std::shared_ptr<std::atomic_bool> &)> behavior;

  remote_usb::usbip_command_result run(
    const std::string &executable,
    const std::vector<std::string> &arguments,
    std::chrono::milliseconds,
    const std::shared_ptr<std::atomic_bool> &cancel,
    std::size_t) {
    {
      std::lock_guard lock(mutex);
      calls.push_back(command_call { executable, arguments });
      condition.notify_all();
    }
    if (behavior) {
      return behavior(arguments, cancel);
    }
    remote_usb::usbip_command_result result;
    result.exit_code = 0;
    result.standard_output = "7\n";
    return result;
  }

  bool wait_calls(std::size_t count) {
    std::unique_lock lock(mutex);
    return condition.wait_for(lock, 2s, [this, count]() {
      return calls.size() >= count;
    });
  }
};

struct result_harness {
  std::mutex mutex;
  std::condition_variable condition;
  std::vector<remote_usb::usbip_host_result> results;

  remote_usb::usbip_host_completion callback() {
    return [this](remote_usb::usbip_host_result result) {
      std::lock_guard lock(mutex);
      results.push_back(std::move(result));
      condition.notify_all();
    };
  }

  bool wait_results(std::size_t count) {
    std::unique_lock lock(mutex);
    return condition.wait_for(lock, 2s, [this, count]() {
      return results.size() >= count;
    });
  }

  remote_usb::usbip_host_result result_at(std::size_t index) {
    std::lock_guard lock(mutex);
    return results.at(index);
  }
};

remote_usb::usbip_host_request
make_request(std::string busid = "1-2") {
  remote_usb::usbip_host_request request;
  request.server_endpoint.address = "127.0.0.1";
  request.server_endpoint.port = 41234;
  request.server_endpoint.busid = std::move(busid);
  return request;
}

remote_usb::usbip_host_controller_config
make_config(command_harness &commands) {
  remote_usb::usbip_host_controller_config config;
  config.executable = "usbip-test";
  config.executable_validator = accept_any_executable;
  config.attach_timeout = 2s;
  config.detach_timeout = 2s;
  config.command_runner = [&commands](
    const std::string &executable,
    const std::vector<std::string> &arguments,
    std::chrono::milliseconds timeout,
    const std::shared_ptr<std::atomic_bool> &cancel,
    std::size_t max_output_bytes) {
    return commands.run(executable, arguments, timeout, cancel, max_output_bytes);
  };
  return config;
}

}  // namespace

static_assert(noexcept(std::declval<remote_usb::usbip_host_controller &>().stop()));

#ifdef REMOTE_USB_PROCESS_TREE_HELPER
TEST(RemoteUsbHostController, DefaultRunnerTerminatesDescendantPipeHolders) {
  remote_usb::usbip_host_controller_config config;
  config.executable = REMOTE_USB_PROCESS_TREE_HELPER;
  config.executable_validator = accept_any_executable;
  config.backend = remote_usb::usbip_host_backend::usbip_win2;
  config.attach_timeout = 5s;
  config.detach_timeout = 5s;
  remote_usb::usbip_host_controller controller(std::move(config));
  result_harness results;

  const auto started = std::chrono::steady_clock::now();
  ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  EXPECT_EQ(results.result_at(0).status, remote_usb::usbip_host_status::ok);
  EXPECT_LT(std::chrono::steady_clock::now() - started, 2s);
}
#endif

TEST(RemoteUsbHostController, ExplicitlyUnsupportedBackendDoesNotLaunchHelper) {
  command_harness commands;
  result_harness results;
  auto config = make_config(commands);
  config.backend = remote_usb::usbip_host_backend::unsupported;
  remote_usb::usbip_host_controller controller(std::move(config));

  EXPECT_EQ(controller.backend(), remote_usb::usbip_host_backend::unsupported);
  EXPECT_FALSE(controller.backend_supported());
  EXPECT_EQ(controller.attach(make_request(), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  EXPECT_EQ(results.result_at(0).status, remote_usb::usbip_host_status::unsupported);
  {
    std::lock_guard lock(commands.mutex);
    EXPECT_TRUE(commands.calls.empty());
  }
  controller.stop();
}

TEST(RemoteUsbHostController, AutomaticBackendIsNativeOnlyWithoutInjectedRunner) {
  remote_usb::usbip_host_controller controller;
#ifdef _WIN32
  EXPECT_EQ(controller.backend(), remote_usb::usbip_host_backend::usbip_win2);
  EXPECT_TRUE(controller.backend_supported());
#else
  EXPECT_EQ(controller.backend(), remote_usb::usbip_host_backend::unsupported);
  EXPECT_FALSE(controller.backend_supported());
#endif
  controller.stop();
}

TEST(RemoteUsbHostController, ReaderThreadCreationFailureReturnsTerminalResult) {
  remote_usb::usbip_host_controller_config config;
#ifdef _WIN32
  const auto command_interpreter = std::getenv("ComSpec");
  ASSERT_NE(command_interpreter, nullptr);
  ASSERT_NE(command_interpreter[0], '\0');
  config.executable = command_interpreter;
  config.executable_validator = accept_any_executable;
#else
  config.executable = "/bin/sh";
#endif
  config.backend = remote_usb::usbip_host_backend::usbip_win2;
  config.attach_timeout = 2s;
  std::atomic_size_t reader_launches { 0 };
  config.reader_thread_factory = [&](std::function<void()> function) {
    if (reader_launches.fetch_add(1, std::memory_order_relaxed) == 1) {
      throw std::system_error(
        std::make_error_code(std::errc::resource_unavailable_try_again),
        "reader thread unavailable");
    }
    return std::thread(std::move(function));
  };

  result_harness results;
  remote_usb::usbip_host_controller controller(std::move(config));
  ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  const auto result = results.result_at(0);
  EXPECT_FALSE(result.ok());
  EXPECT_NE(result.detail.find("reader thread unavailable"), std::string::npos);
  EXPECT_EQ(reader_launches.load(std::memory_order_relaxed), 2U);
  controller.stop();
}

TEST(RemoteUsbHostController, DifferentEndpointsCanRunConcurrently) {
  command_harness commands;
  result_harness results;
  std::mutex behavior_mutex;
  std::condition_variable behavior_condition;
  bool first_started = false;
  bool release_first = false;
  std::size_t attach_count = 0;
  commands.behavior = [&](const std::vector<std::string> &arguments,
                          const std::shared_ptr<std::atomic_bool> &cancel) {
    const bool attach = std::find(arguments.begin(), arguments.end(), "attach") !=
                        arguments.end();
    remote_usb::usbip_command_result result;
    if (!attach) {
      result.exit_code = 0;
      return result;
    }

    std::size_t ordinal = 0;
    {
      std::unique_lock lock(behavior_mutex);
      ordinal = ++attach_count;
      if (ordinal == 1) {
        first_started = true;
        behavior_condition.notify_all();
        behavior_condition.wait(lock, [&]() {
          return release_first || cancel->load(std::memory_order_acquire);
        });
      }
    }
    if (cancel->load(std::memory_order_acquire)) {
      result.cancelled = true;
      result.exit_code = -1;
      return result;
    }
    result.exit_code = 0;
    result.standard_output = ordinal == 1 ? "7\n" : "8\n";
    return result;
  };

  remote_usb::usbip_host_controller controller(make_config(commands));
  const auto first_id = controller.attach(make_request("1-11"), results.callback());
  ASSERT_NE(first_id, 0U);
  {
    std::unique_lock lock(behavior_mutex);
    ASSERT_TRUE(behavior_condition.wait_for(lock, 2s, [&]() { return first_started; }));
  }

  /* The first operation is still active.  A different busid is a different
   * device and must not be rejected as the old device's twin. */
  const auto second_id = controller.attach(make_request("1-12"), results.callback());
  ASSERT_NE(second_id, 0U);
  ASSERT_TRUE(commands.wait_calls(2));
  {
    std::lock_guard lock(behavior_mutex);
    release_first = true;
  }
  behavior_condition.notify_all();
  ASSERT_TRUE(results.wait_results(2));

  remote_usb::usbip_host_binding first_binding;
  remote_usb::usbip_host_binding second_binding;
  {
    std::lock_guard lock(results.mutex);
    for (const auto &result : results.results) {
      ASSERT_TRUE(result.ok()) << result.detail;
      ASSERT_TRUE(result.binding.has_value());
      if (result.binding->server_endpoint.busid == "1-11") {
        first_binding = *result.binding;
      } else if (result.binding->server_endpoint.busid == "1-12") {
        second_binding = *result.binding;
      }
    }
  }
  ASSERT_EQ(first_binding.server_endpoint.busid, "1-11");
  ASSERT_EQ(second_binding.server_endpoint.busid, "1-12");
  ASSERT_NE(controller.detach(first_binding, results.callback()), 0U);
  ASSERT_NE(controller.detach(second_binding, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(4));
  EXPECT_TRUE(results.result_at(2).ok());
  EXPECT_TRUE(results.result_at(3).ok());
  controller.stop();
}

TEST(RemoteUsbHostController, DifferentEndpointsCanBeAccepted) {
  command_harness commands;
  result_harness results;
  remote_usb::usbip_host_controller controller(make_config(commands));

  ASSERT_NE(controller.attach(make_request("1-13"), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  ASSERT_TRUE(results.result_at(0).ok());
  ASSERT_TRUE(results.result_at(0).binding.has_value());

  /* The first binding is already accepted.  A different busid is a different
   * device and must be accepted. */
  ASSERT_NE(controller.attach(make_request("1-14"), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(2));
  EXPECT_TRUE(results.result_at(1).ok());
  ASSERT_TRUE(results.result_at(1).binding.has_value());
  EXPECT_EQ(results.result_at(0).binding->server_endpoint.busid, "1-13");
  EXPECT_EQ(results.result_at(1).binding->server_endpoint.busid, "1-14");

  ASSERT_NE(controller.detach(*results.result_at(0).binding, results.callback()), 0U);
  ASSERT_NE(controller.detach(*results.result_at(1).binding, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(4));
  EXPECT_TRUE(results.result_at(2).ok());
  EXPECT_TRUE(results.result_at(3).ok());
  controller.stop();
}

TEST(RemoteUsbHostController, UsesUsbipWin2ArgumentContractAndTracksBinding) {
  command_harness commands;
  result_harness results;
  remote_usb::usbip_host_controller controller(make_config(commands));
  EXPECT_EQ(controller.backend(), remote_usb::usbip_host_backend::usbip_win2);
  EXPECT_TRUE(controller.backend_supported());

  const auto request = make_request();
  ASSERT_NE(controller.attach(request, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  const auto attached = results.result_at(0);
  ASSERT_TRUE(attached.ok()) << attached.detail;
  ASSERT_TRUE(attached.binding.has_value());
  EXPECT_EQ(attached.binding->hub_port, 7U);

  ASSERT_TRUE(commands.wait_calls(1));
  {
    std::lock_guard lock(commands.mutex);
    ASSERT_EQ(commands.calls.front().executable, "usbip-test");
    const std::vector<std::string> expected {
      "--tcp-port", "41234", "attach", "--remote", "127.0.0.1",
      "--bus-id", "1-2", "--once", "--terse"
    };
    EXPECT_EQ(commands.calls.front().arguments, expected);
  }

  ASSERT_NE(controller.detach(*attached.binding, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(2));
  const auto detached = results.result_at(1);
  EXPECT_TRUE(detached.ok()) << detached.detail;
  ASSERT_TRUE(commands.wait_calls(2));
  {
    std::lock_guard lock(commands.mutex);
    const std::vector<std::string> expected { "detach", "--port", "7" };
    EXPECT_EQ(commands.calls.at(1).arguments, expected);
  }
  controller.stop();
}

TEST(RemoteUsbHostController, RejectsDuplicateEndpointAndUnknownBinding) {
  command_harness commands;
  result_harness results;
  remote_usb::usbip_host_controller controller(make_config(commands));
  const auto request = make_request();

  ASSERT_NE(controller.attach(request, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  ASSERT_TRUE(results.result_at(0).ok());
  const auto duplicate_id = controller.attach(request, results.callback());
  EXPECT_EQ(duplicate_id, 0U);
  ASSERT_TRUE(results.wait_results(2));
  EXPECT_EQ(results.result_at(1).status, remote_usb::usbip_host_status::busy);

  auto unknown = *results.result_at(0).binding;
  unknown.hub_port = 8;
  EXPECT_EQ(controller.detach(unknown, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(3));
  EXPECT_EQ(results.result_at(2).status,
            remote_usb::usbip_host_status::invalid_argument);
  controller.stop();
}

TEST(RemoteUsbHostController, RejectsStaleBindingAfterEndpointAndHubPortReuse) {
  command_harness commands;
  result_harness results;
  remote_usb::usbip_host_controller controller(make_config(commands));
  const auto request = make_request();

  ASSERT_NE(controller.attach(request, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  ASSERT_TRUE(results.result_at(0).ok());
  ASSERT_TRUE(results.result_at(0).binding.has_value());
  const auto old_binding = *results.result_at(0).binding;
  ASSERT_NE(controller.detach(old_binding, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(2));
  ASSERT_TRUE(results.result_at(1).ok());

  ASSERT_NE(controller.attach(request, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(3));
  ASSERT_TRUE(results.result_at(2).ok());
  ASSERT_TRUE(results.result_at(2).binding.has_value());
  const auto new_binding = *results.result_at(2).binding;
  ASSERT_EQ(old_binding.server_endpoint, new_binding.server_endpoint);
  ASSERT_EQ(old_binding.hub_port, new_binding.hub_port);
  EXPECT_NE(old_binding.binding_id, new_binding.binding_id);
  EXPECT_EQ(controller.detach(old_binding, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(4));
  EXPECT_EQ(results.result_at(3).status, remote_usb::usbip_host_status::invalid_argument);
  {
    std::lock_guard lock(commands.mutex);
    EXPECT_EQ(commands.calls.size(), 3U);
  }
  ASSERT_NE(controller.detach(new_binding, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(5));
  EXPECT_TRUE(results.result_at(4).ok());
  controller.stop();
}

TEST(RemoteUsbHostController, RejectsUnsafeEndpointsAndMalformedHubPorts) {
  const auto expect_rejected_request = [](remote_usb::usbip_host_request request) {
    command_harness commands;
    result_harness results;
    remote_usb::usbip_host_controller controller(make_config(commands));
    EXPECT_EQ(controller.attach(std::move(request), results.callback()), 0U);
    EXPECT_TRUE(results.wait_results(1));
    EXPECT_EQ(results.result_at(0).status,
              remote_usb::usbip_host_status::invalid_argument);
    {
      std::lock_guard lock(commands.mutex);
      EXPECT_TRUE(commands.calls.empty());
    }
    controller.stop();
  };

  auto non_loopback = make_request();
  non_loopback.server_endpoint.address = "203.0.113.10";
  expect_rejected_request(std::move(non_loopback));

  auto oversized_busid = make_request();
  oversized_busid.server_endpoint.busid.assign(32, 'a');
  expect_rejected_request(std::move(oversized_busid));

  auto non_printable_busid = make_request();
  non_printable_busid.server_endpoint.busid = "usb";
  non_printable_busid.server_endpoint.busid.push_back('\x1f');
  non_printable_busid.server_endpoint.busid += "device";
  expect_rejected_request(std::move(non_printable_busid));

  {
    command_harness commands;
    result_harness results;
    remote_usb::usbip_host_controller controller(make_config(commands));
    auto maximum_busid = make_request();
    maximum_busid.server_endpoint.busid = "1-" + std::string(29, '1');
    ASSERT_NE(controller.attach(std::move(maximum_busid), results.callback()), 0U);
    ASSERT_TRUE(results.wait_results(1));
    EXPECT_TRUE(results.result_at(0).ok());
    controller.stop();
  }

  for (const std::string output : { "", "0", "256", "not-a-port" }) {
    SCOPED_TRACE(output);
    command_harness commands;
    result_harness results;
    commands.behavior = [output](const std::vector<std::string> &,
                                 const std::shared_ptr<std::atomic_bool> &) {
      remote_usb::usbip_command_result result;
      result.exit_code = 0;
      result.standard_output = output;
      return result;
    };
    remote_usb::usbip_host_controller controller(make_config(commands));
    ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
    ASSERT_TRUE(results.wait_results(1));
    EXPECT_EQ(results.result_at(0).status,
              remote_usb::usbip_host_status::attach_failed);
    controller.stop();
  }
}

TEST(RemoteUsbHostController, CancellationIsPropagatedAndStopJoinsWorker) {
  command_harness commands;
  result_harness results;
  std::mutex behavior_mutex;
  std::condition_variable behavior_condition;
  bool started = false;
  commands.behavior = [&](const std::vector<std::string> &,
                          const std::shared_ptr<std::atomic_bool> &cancel) {
    {
      std::lock_guard lock(behavior_mutex);
      started = true;
      behavior_condition.notify_all();
    }
    while (!cancel->load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(1ms);
    }
    remote_usb::usbip_command_result result;
    result.cancelled = true;
    result.exit_code = -1;
    return result;
  };

  remote_usb::usbip_host_controller controller(make_config(commands));
  const auto id = controller.attach(make_request(), results.callback());
  ASSERT_NE(id, 0U);
  {
    std::unique_lock lock(behavior_mutex);
    ASSERT_TRUE(behavior_condition.wait_for(lock, 2s, [&]() { return started; }));
  }
  ASSERT_TRUE(controller.cancel(id));
  ASSERT_TRUE(results.wait_results(1));
  EXPECT_EQ(results.result_at(0).status, remote_usb::usbip_host_status::cancelled);
  EXPECT_FALSE(controller.cancel(id));
  controller.stop();
  EXPECT_TRUE(controller.stopped());
}

TEST(RemoteUsbHostController, ConcurrentStopWaitsForTheOwningStop) {
  command_harness commands;
  result_harness results;
  std::mutex behavior_mutex;
  std::condition_variable behavior_condition;
  bool entered = false;
  bool cancellation_seen = false;
  bool release = false;
  commands.behavior = [&](const std::vector<std::string> &,
                          const std::shared_ptr<std::atomic_bool> &cancel) {
    {
      std::lock_guard lock(behavior_mutex);
      entered = true;
      behavior_condition.notify_all();
    }
    std::unique_lock lock(behavior_mutex);
    while (!cancel->load(std::memory_order_acquire)) {
      behavior_condition.wait_for(lock, 1ms);
    }
    cancellation_seen = true;
    behavior_condition.notify_all();
    behavior_condition.wait(lock, [&]() { return release; });
    remote_usb::usbip_command_result result;
    result.cancelled = true;
    result.exit_code = -1;
    return result;
  };

  remote_usb::usbip_host_controller controller(make_config(commands));
  ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
  {
    std::unique_lock lock(behavior_mutex);
    ASSERT_TRUE(behavior_condition.wait_for(lock, 2s, [&]() { return entered; }));
  }

  std::atomic_bool first_done { false };
  std::atomic_bool second_done { false };
  std::thread first_stop([&]() {
    controller.stop();
    first_done.store(true, std::memory_order_release);
  });
  {
    std::unique_lock lock(behavior_mutex);
    ASSERT_TRUE(behavior_condition.wait_for(lock, 2s, [&]() {
      return cancellation_seen;
    }));
  }

  std::thread second_stop([&]() {
    controller.stop();
    second_done.store(true, std::memory_order_release);
  });
  /* The helper is intentionally held open.  The second caller must not return
   * until the first stop has joined it and completed cleanup. */
  std::this_thread::sleep_for(20ms);
  EXPECT_FALSE(second_done.load(std::memory_order_acquire));
  {
    std::lock_guard lock(behavior_mutex);
    release = true;
  }
  behavior_condition.notify_all();
  first_stop.join();
  second_stop.join();
  EXPECT_TRUE(first_done.load(std::memory_order_acquire));
  EXPECT_TRUE(second_done.load(std::memory_order_acquire));
}

TEST(RemoteUsbHostController, RunnerExceptionsBecomeTerminalResults) {
  command_harness commands;
  result_harness results;
  commands.behavior = [](const std::vector<std::string> &,
                         const std::shared_ptr<std::atomic_bool> &)
    -> remote_usb::usbip_command_result {
    throw std::runtime_error("runner unavailable");
  };

  remote_usb::usbip_host_controller controller(make_config(commands));
  ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  const auto result = results.result_at(0);
  EXPECT_EQ(result.status, remote_usb::usbip_host_status::attach_failed);
  EXPECT_EQ(result.detail, "runner unavailable");
  EXPECT_EQ(controller.active_operations(), 0U);
  controller.stop();
}

TEST(RemoteUsbHostController, DetachRunnerExceptionDoesNotTerminateStop) {
  command_harness commands;
  result_harness results;
  bool throw_on_detach = false;
  commands.behavior = [&throw_on_detach](
                         const std::vector<std::string> &arguments,
                         const std::shared_ptr<std::atomic_bool> &) {
    remote_usb::usbip_command_result result;
    const bool detach = std::find(arguments.begin(), arguments.end(), "detach") !=
                        arguments.end();
    if (detach && throw_on_detach) {
      throw std::runtime_error("detach runner unavailable");
    }
    result.exit_code = 0;
    result.standard_output = "7\n";
    return result;
  };

  remote_usb::usbip_host_controller controller(make_config(commands));
  ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  ASSERT_TRUE(results.result_at(0).ok());
  throw_on_detach = true;
  ASSERT_NE(controller.detach(*results.result_at(0).binding, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(2));
  EXPECT_EQ(results.result_at(1).status, remote_usb::usbip_host_status::detach_failed);
  EXPECT_EQ(results.result_at(1).detail, "detach runner unavailable");
  EXPECT_NO_THROW(controller.stop());
}

TEST(RemoteUsbHostController, LateAttachCompletionUsesLiveDetachToken) {
  command_harness commands;
  result_harness results;
  std::mutex behavior_mutex;
  std::condition_variable behavior_condition;
  bool attach_started = false;
  bool detach_succeeded = false;
  bool detach_saw_cancel = false;
  commands.behavior = [&](const std::vector<std::string> &arguments,
                          const std::shared_ptr<std::atomic_bool> &cancel) {
    remote_usb::usbip_command_result result;
    if (std::find(arguments.begin(), arguments.end(), "attach") != arguments.end()) {
      {
        std::lock_guard lock(behavior_mutex);
        attach_started = true;
        behavior_condition.notify_all();
      }
      while (!cancel->load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(1ms);
      }
      /* Simulate the ioctl completing successfully just as cancellation wins. */
      result.exit_code = 0;
      result.standard_output = "7\n";
      return result;
    }

    {
      std::lock_guard lock(behavior_mutex);
      detach_saw_cancel = cancel->load(std::memory_order_acquire);
      detach_succeeded = !detach_saw_cancel;
      behavior_condition.notify_all();
    }
    result.exit_code = detach_succeeded ? 0 : -1;
    result.cancelled = detach_saw_cancel;
    return result;
  };

  remote_usb::usbip_host_controller controller(make_config(commands));
  const auto id = controller.attach(make_request(), results.callback());
  ASSERT_NE(id, 0U);
  {
    std::unique_lock lock(behavior_mutex);
    ASSERT_TRUE(behavior_condition.wait_for(lock, 2s, [&]() { return attach_started; }));
  }
  ASSERT_TRUE(controller.cancel(id));
  ASSERT_TRUE(results.wait_results(1));
  EXPECT_EQ(results.result_at(0).status, remote_usb::usbip_host_status::cancelled);
  ASSERT_TRUE(commands.wait_calls(2));
  {
    std::lock_guard lock(behavior_mutex);
    EXPECT_FALSE(detach_saw_cancel);
    EXPECT_TRUE(detach_succeeded);
  }
  controller.stop();
}

TEST(RemoteUsbHostController, StopRetriesFailedLateAttachCompensation) {
  command_harness commands;
  result_harness results;
  std::mutex behavior_mutex;
  std::condition_variable behavior_condition;
  bool attach_started = false;
  std::size_t detach_attempts = 0;
  commands.behavior = [&](const std::vector<std::string> &arguments,
                          const std::shared_ptr<std::atomic_bool> &cancel) {
    remote_usb::usbip_command_result result;
    if (std::find(arguments.begin(), arguments.end(), "attach") != arguments.end()) {
      {
        std::lock_guard lock(behavior_mutex);
        attach_started = true;
        behavior_condition.notify_all();
      }
      while (!cancel->load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(1ms);
      }
      result.exit_code = 0;
      result.standard_output = "7\n";
      return result;
    }

    {
      std::lock_guard lock(behavior_mutex);
      ++detach_attempts;
      result.exit_code = detach_attempts == 1 ? 1 : 0;
    }
    return result;
  };

  remote_usb::usbip_host_controller controller(make_config(commands));
  ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
  {
    std::unique_lock lock(behavior_mutex);
    ASSERT_TRUE(behavior_condition.wait_for(lock, 2s, [&]() {
      return attach_started;
    }));
  }

  controller.stop();
  ASSERT_TRUE(results.wait_results(1));
  EXPECT_EQ(results.result_at(0).status, remote_usb::usbip_host_status::cancelled);
  EXPECT_TRUE(commands.wait_calls(3));
  {
    std::lock_guard lock(behavior_mutex);
    EXPECT_EQ(detach_attempts, 2U);
  }
}

TEST(RemoteUsbHostController, CompletionMayCallStopFromWorker) {
  command_harness commands;
  std::mutex callback_mutex;
  std::condition_variable callback_condition;
  bool callback_done = false;
  std::unique_ptr<remote_usb::usbip_host_controller> controller;
  controller = std::make_unique<remote_usb::usbip_host_controller>(make_config(commands));

  const auto id = controller->attach(
    make_request(),
    [&](remote_usb::usbip_host_result result) {
      EXPECT_TRUE(result.ok()) << result.detail;
      controller->stop();
      std::lock_guard lock(callback_mutex);
      callback_done = true;
      callback_condition.notify_all();
    });
  ASSERT_NE(id, 0U);
  {
    std::unique_lock lock(callback_mutex);
    ASSERT_TRUE(callback_condition.wait_for(lock, 2s, [&]() { return callback_done; }));
  }
  EXPECT_TRUE(controller->stopped());
  controller.reset();
}

TEST(RemoteUsbHostController, CompletionMayScheduleDetachForSameLease) {
  command_harness commands;
  std::mutex callback_mutex;
  std::condition_variable callback_condition;
  bool attach_done = false;
  bool detach_done = false;
  remote_usb::usbip_host_controller::operation_id nested_detach_id = 0;
  remote_usb::usbip_host_status detach_status =
    remote_usb::usbip_host_status::invalid_argument;
  remote_usb::usbip_host_controller controller(make_config(commands));

  const auto attach_id = controller.attach(
    make_request(),
    [&](remote_usb::usbip_host_result result) {
      if (result.ok() && result.binding) {
        nested_detach_id = controller.detach(
          *result.binding,
          [&](remote_usb::usbip_host_result detach_result) {
            {
              std::lock_guard lock(callback_mutex);
              detach_status = detach_result.status;
              detach_done = true;
            }
            callback_condition.notify_all();
          });
      }
      {
        std::lock_guard lock(callback_mutex);
        attach_done = true;
      }
      callback_condition.notify_all();
    });
  ASSERT_NE(attach_id, 0U);
  {
    std::unique_lock lock(callback_mutex);
    ASSERT_TRUE(callback_condition.wait_for(lock, 2s, [&]() {
      return attach_done && detach_done;
    }));
  }
  EXPECT_NE(nested_detach_id, 0U);
  EXPECT_EQ(detach_status, remote_usb::usbip_host_status::ok);
  ASSERT_TRUE(commands.wait_calls(2));
  {
    std::lock_guard lock(commands.mutex);
    ASSERT_EQ(commands.calls.size(), 2U);
    EXPECT_EQ(commands.calls.at(1).arguments,
              (std::vector<std::string> { "detach", "--port", "7" }));
  }
  controller.stop();
}

TEST(RemoteUsbHostController, ExternalDispatchDoesNotJoinActiveCompletion) {
  command_harness commands;
  remote_usb::usbip_host_controller controller(make_config(commands));

  std::mutex callback_mutex;
  std::condition_variable callback_condition;
  bool callback_entered = false;
  bool release_callback = false;
  bool dispatch_returned = false;
  bool detach_completed = false;
  std::optional<remote_usb::usbip_host_binding> attached_binding;

  const auto attach_id = controller.attach(
    make_request(),
    [&](remote_usb::usbip_host_result result) {
      ASSERT_TRUE(result.ok()) << result.detail;
      ASSERT_TRUE(result.binding.has_value());
      {
        std::lock_guard lock(callback_mutex);
        attached_binding = *result.binding;
        callback_entered = true;
      }
      callback_condition.notify_all();

      std::unique_lock lock(callback_mutex);
      callback_condition.wait(lock, [&]() { return release_callback; });
    });
  ASSERT_NE(attach_id, 0U);

  std::thread external_dispatch([&]() {
    remote_usb::usbip_host_binding binding;
    {
      std::unique_lock lock(callback_mutex);
      callback_condition.wait(lock, [&]() {
        return attached_binding.has_value();
      });
      binding = *attached_binding;
    }

    const auto detach_id = controller.detach(
      std::move(binding),
      [&](remote_usb::usbip_host_result result) {
        EXPECT_TRUE(result.ok()) << result.detail;
        {
          std::lock_guard lock(callback_mutex);
          detach_completed = true;
        }
        callback_condition.notify_all();
      });
    EXPECT_NE(detach_id, 0U);
    {
      std::lock_guard lock(callback_mutex);
      dispatch_returned = true;
    }
    callback_condition.notify_all();
  });

  {
    std::unique_lock lock(callback_mutex);
    ASSERT_TRUE(callback_condition.wait_for(lock, 2s, [&]() {
      return callback_entered;
    }));
    /* The attach completion is intentionally blocked.  A dispatch from a
     * different thread must not try to join that worker while its callback
     * is still on the stack. */
    EXPECT_TRUE(callback_condition.wait_for(lock, 1s, [&]() {
      return dispatch_returned;
    }));
    release_callback = true;
  }
  callback_condition.notify_all();

  {
    std::unique_lock lock(callback_mutex);
    ASSERT_TRUE(callback_condition.wait_for(lock, 2s, [&]() {
      return detach_completed;
    }));
  }
  external_dispatch.join();
  controller.stop();
}

/* ---- additions for ApolloVibe: absolute executable path and strict bus ids ---- */

TEST(RemoteUsbHostController, DefaultExecutableIsTheAbsoluteProgramFilesPath) {
  const auto path = remote_usb::usbip_host_controller::default_executable();
  const auto *program_files = std::getenv("ProgramW6432");
  ASSERT_NE(program_files, nullptr);

  ASSERT_FALSE(path.empty());
  ASSERT_GT(path.size(), 3U);
  EXPECT_EQ(path[1], ':');
  EXPECT_EQ(path[2], '\\');
  std::string expected = std::string(program_files) + "\\USBip\\usbip.exe";
  std::string actual = path;
  const auto lower = [](std::string &text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  };
  lower(expected);
  lower(actual);
  EXPECT_EQ(actual, expected);
}

TEST(RemoteUsbHostController, ARelativeExecutableIsRefusedAndNeverLaunched) {
  /* Plant a usbip.exe in a directory that is both on PATH and the current directory. A controller that
   * searched PATH or the working directory would find it. The default check must refuse before any launch. */
  const auto directory = std::filesystem::temp_directory_path() / "apollovibe_usbip_path_plant";
  std::filesystem::create_directories(directory);
  { std::ofstream(directory / "usbip.exe") << "not a program"; }
  const auto old_path = std::string(std::getenv("PATH") ? std::getenv("PATH") : "");
  const auto old_directory = std::filesystem::current_path();
  _putenv_s("PATH", (directory.string() + ";" + old_path).c_str());
  std::filesystem::current_path(directory);

  command_harness commands;
  result_harness results;
  auto config = make_config(commands);
  config.executable = "usbip.exe";
  config.executable_validator = nullptr;  // the production check
  remote_usb::usbip_host_controller controller(std::move(config));

  ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
  const bool completed = results.wait_results(1);
  controller.stop();

  std::filesystem::current_path(old_directory);
  _putenv_s("PATH", old_path.c_str());
  std::error_code ignored;
  std::filesystem::remove_all(directory, ignored);

  ASSERT_TRUE(completed);
  const auto result = results.result_at(0);
  EXPECT_EQ(result.status, remote_usb::usbip_host_status::launch_failed);
  EXPECT_NE(result.detail.find("refused"), std::string::npos) << result.detail;
  std::lock_guard lock(commands.mutex);
  EXPECT_TRUE(commands.calls.empty());
}

TEST(RemoteUsbHostController, TheExecutableIsCheckedBeforeEveryAttachAndDetach) {
  command_harness commands;
  result_harness results;
  auto config = make_config(commands);
  std::atomic_size_t checks { 0 };
  std::string checked_path;
  std::mutex checked_mutex;
  config.executable = "C:\\Fake\\USBip\\usbip.exe";
  config.executable_validator = [&](const std::string &path) {
    std::lock_guard lock(checked_mutex);
    checked_path = path;
    ++checks;
    return remote_usb::executable_check { true, {} };
  };
  remote_usb::usbip_host_controller controller(std::move(config));

  ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  ASSERT_TRUE(results.result_at(0).ok());
  EXPECT_EQ(checks.load(), 1U);
  ASSERT_NE(controller.detach(*results.result_at(0).binding, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(2));
  EXPECT_EQ(checks.load(), 2U);
  {
    std::lock_guard lock(checked_mutex);
    EXPECT_EQ(checked_path, "C:\\Fake\\USBip\\usbip.exe");
  }
  /* The runner got exactly the path that was checked. */
  std::lock_guard lock(commands.mutex);
  ASSERT_EQ(commands.calls.size(), 2U);
  EXPECT_EQ(commands.calls[0].executable, "C:\\Fake\\USBip\\usbip.exe");
  EXPECT_EQ(commands.calls[1].executable, "C:\\Fake\\USBip\\usbip.exe");
}

TEST(RemoteUsbHostController, ARefusedExecutableFailsAttachAndDetachWithoutLaunching) {
  command_harness commands;
  result_harness results;
  auto config = make_config(commands);
  std::atomic_bool trusted { true };
  config.executable_validator = [&trusted](const std::string &) {
    return trusted ? remote_usb::executable_check { true, {} }
                   : remote_usb::executable_check { false, "directory is writable by users" };
  };
  remote_usb::usbip_host_controller controller(std::move(config));

  ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  ASSERT_TRUE(results.result_at(0).ok());
  const auto binding = *results.result_at(0).binding;

  trusted = false;  // the location became writable after the attach
  ASSERT_NE(controller.detach(binding, results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(2));
  const auto detach = results.result_at(1);
  EXPECT_EQ(detach.status, remote_usb::usbip_host_status::launch_failed);
  EXPECT_NE(detach.detail.find("directory is writable by users"), std::string::npos) << detach.detail;
  {
    std::lock_guard lock(commands.mutex);
    EXPECT_EQ(commands.calls.size(), 1U) << "only the first attach may have reached the runner";
  }

  ASSERT_NE(controller.attach(make_request("1-3"), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(3));
  EXPECT_EQ(results.result_at(2).status, remote_usb::usbip_host_status::launch_failed);
  {
    std::lock_guard lock(commands.mutex);
    EXPECT_EQ(commands.calls.size(), 1U);
  }
  trusted = true;  // let stop() detach what is still attached
  controller.stop();
}

TEST(RemoteUsbHostController, AValidatorThatThrowsRefuses) {
  command_harness commands;
  result_harness results;
  auto config = make_config(commands);
  config.executable_validator = [](const std::string &) -> remote_usb::executable_check {
    throw std::runtime_error("boom");
  };
  remote_usb::usbip_host_controller controller(std::move(config));

  ASSERT_NE(controller.attach(make_request(), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  EXPECT_EQ(results.result_at(0).status, remote_usb::usbip_host_status::launch_failed);
  std::lock_guard lock(commands.mutex);
  EXPECT_TRUE(commands.calls.empty());
}

TEST(RemoteUsbBusId, OnlyTheNumericShapeReachesACommandLine) {
  for (const char *good : { "1-2", "12-34", "1-2.3", "3-14.1.2", "9-9" }) {
    SCOPED_TRACE(good);
    EXPECT_TRUE(remote_usb::valid_usbip_busid_shape(good));
    EXPECT_TRUE(remote_usb::valid_busid_charset(good));
  }
  /* Valid on the wire (the client allows them) but not a numeric bus id. */
  for (const char *wire_only : { "1-9:0", "usb", "a-b", "1-2a", "0-1", "1-0", "01-2", "1-", "-1", "1", "1-2.", "1-2..3", "1-2.x", "1.2-3" }) {
    SCOPED_TRACE(wire_only);
    EXPECT_FALSE(remote_usb::valid_usbip_busid_shape(wire_only));
  }
  for (const char *bad_wire : { "", "--help", "-1-2", "1-2 ", "1 -2", "1-2;calc", "1-2&x", "1-2\"", "..\\1-2", "1-2\n", "1-2%20", "\xC3\xA9" }) {
    SCOPED_TRACE(bad_wire);
    EXPECT_FALSE(remote_usb::valid_usbip_busid_shape(bad_wire));
  }
  EXPECT_FALSE(remote_usb::valid_busid_charset(""));
  EXPECT_TRUE(remote_usb::valid_busid_charset(std::string(31, 'a')));
  EXPECT_FALSE(remote_usb::valid_busid_charset(std::string(32, 'a')));
  EXPECT_TRUE(remote_usb::valid_busid_charset("1-9:0"));
  EXPECT_FALSE(remote_usb::valid_busid_charset("a b"));
}

TEST(RemoteUsbHostController, RefusesBusIdsThatAreNotNumericBeforeAnyLaunch) {
  command_harness commands;
  result_harness results;
  remote_usb::usbip_host_controller controller(make_config(commands));

  std::size_t expected_results = 0;
  for (const char *bad : { "--help", "-1-2", "usbip-test", "1-2;calc", "1-2 --foo", "a-b", "1-9:0" }) {
    SCOPED_TRACE(bad);
    EXPECT_EQ(controller.attach(make_request(bad), results.callback()), 0U);
    ASSERT_TRUE(results.wait_results(++expected_results));
    EXPECT_EQ(results.result_at(expected_results - 1).status, remote_usb::usbip_host_status::invalid_argument);
  }
  std::lock_guard lock(commands.mutex);
  EXPECT_TRUE(commands.calls.empty());
}

TEST(RemoteUsbHostController, ArgumentsAreSeparateVectorElementsNeverAJoinedCommandLine) {
  command_harness commands;
  result_harness results;
  remote_usb::usbip_host_controller controller(make_config(commands));

  ASSERT_NE(controller.attach(make_request("12-34.5"), results.callback()), 0U);
  ASSERT_TRUE(results.wait_results(1));
  std::lock_guard lock(commands.mutex);
  ASSERT_EQ(commands.calls.size(), 1U);
  for (const auto &argument : commands.calls.front().arguments) {
    EXPECT_EQ(argument.find(' '), std::string::npos) << "argument contains a space: " << argument;
  }
  EXPECT_EQ(commands.calls.front().arguments[5], "--bus-id");
  EXPECT_EQ(commands.calls.front().arguments[6], "12-34.5");
}


TEST(RemoteUsbHostController, TheHelperStartsInItsOwnDirectoryWithAMinimalEnvironment) {
  /* A real launch of a harmless program (cmd.exe, standing in for usbip.exe). The test process has a
   * different working directory holding a planted file, and a variable the helper must not see. */
  const char *interpreter = std::getenv("ComSpec");
  ASSERT_NE(interpreter, nullptr);
  const auto planted_directory = std::filesystem::temp_directory_path() / "apollovibe_helper_cwd_plant";
  std::filesystem::create_directories(planted_directory);
  { std::ofstream(planted_directory / "planted.txt") << "x"; }
  const auto old_directory = std::filesystem::current_path();
  std::filesystem::current_path(planted_directory);
  _putenv_s("APOLLOVIBE_TEST_SECRET", "leaked");

  const auto cancel = std::make_shared<std::atomic_bool>(false);
  const auto result = remote_usb::run_helper_process(
    interpreter,
    { "/c", "cd", "&", "echo", "PATH=%PATH%", "&", "echo", "SECRET=%APOLLOVIBE_TEST_SECRET%", "&", "if", "exist", "planted.txt", "(echo", "PLANTED)", "else", "(echo", "CLEAN)" },
    10s, cancel, 8192);

  _putenv_s("APOLLOVIBE_TEST_SECRET", "");
  std::filesystem::current_path(old_directory);
  std::error_code ignored;
  std::filesystem::remove_all(planted_directory, ignored);

  ASSERT_EQ(result.exit_code, 0) << result.standard_error;
  std::vector<std::string> lines;
  {
    std::string line;
    for (const char c : result.standard_output) {
      if (c == '\n') {
        while (!line.empty() && line.back() == ' ') {
          line.pop_back();  // cmd's "echo x & ..." keeps the space before the ampersand
        }
        lines.push_back(line);
        line.clear();
      } else if (c != '\r') {
        line.push_back(c);
      }
    }
  }
  ASSERT_GE(lines.size(), 4U) << result.standard_output;
  const auto lower = [](std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
  };
  const auto own_directory = std::filesystem::path(interpreter).parent_path().string();
  EXPECT_EQ(lower(lines[0]), lower(own_directory)) << "the helper started in the caller's directory";
  EXPECT_EQ(lower(lines[1]), lower("PATH=" + own_directory)) << "the helper inherited the caller's PATH";
  EXPECT_EQ(lines[2], "SECRET=%APOLLOVIBE_TEST_SECRET%") << "the helper inherited a variable of the caller";
  EXPECT_EQ(lines[3], "CLEAN") << "the helper saw a file planted in the caller's directory";
}

#endif  // _WIN32
